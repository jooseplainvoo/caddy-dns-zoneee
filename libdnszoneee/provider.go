// Package libdnszoneee implements a libdns provider for Zone.ee (api.zone.eu/v2).
// Scope: TXT append/delete only — enough for ACME DNS-01.
package libdnszoneee

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/libdns/libdns"
)

const defaultBaseURL = "https://api.zone.eu/v2/dns/"

type Provider struct {
	Username string `json:"username,omitempty"`
	APIKey   string `json:"api_key,omitempty"`

	baseURL string     // empty → defaultBaseURL; set only by tests in this package
	mu      sync.Mutex // serialize API calls
}

var client = &http.Client{
	Timeout: 30 * time.Second,
	// Never follow redirects: the Authorization header must not go anywhere else.
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type txtRecord struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	Destination string `json:"destination"`
}

func (p *Provider) base() string {
	if p.baseURL != "" {
		return p.baseURL
	}
	return defaultBaseURL
}

func (p *Provider) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, p.base()+path, rdr)
	if err != nil {
		return err
	}
	req.SetBasicAuth(p.Username, p.APIKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("zoneee: %s %s: %w", method, path, err)
	}
	defer func() {
		// Drain so the connection can be reused; cap it so a huge body can't stall us.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("zoneee: %s %s: HTTP %d: %s",
			method, path, resp.StatusCode, bytes.TrimSpace(excerpt))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("zoneee: %s %s: decoding response: %w", method, path, err)
		}
	}
	return nil
}

// libdns: zone "example.com.", name "_acme-challenge"
// API:    zone "example.com",  name "_acme-challenge.example.com"
func names(zone, rel string) (apiZone, fqdn string) {
	apiZone = strings.TrimSuffix(zone, ".")
	fqdn = strings.TrimSuffix(libdns.AbsoluteName(rel, zone), ".")
	return
}

func txtPath(apiZone string) string {
	return url.PathEscape(apiZone) + "/txt"
}

func (p *Provider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var added []libdns.Record
	for _, rec := range recs {
		rr := rec.RR()
		if rr.Type != "TXT" {
			return added, fmt.Errorf("zoneee: only TXT records are supported, got %q", rr.Type)
		}
		apiZone, fqdn := names(zone, rr.Name)
		// Response body intentionally not decoded: the record exists once we get 2xx,
		// and a decode failure here would make the caller think it doesn't.
		if err := p.do(ctx, http.MethodPost, txtPath(apiZone),
			txtRecord{Name: fqdn, Destination: rr.Data}, nil); err != nil {
			return added, err
		}
		added = append(added, rec)
	}
	return added, nil
}

// DeleteRecords deletes TXT records matching name AND value exactly.
// Deliberate deviation from the libdns spec: empty Data is NOT a wildcard —
// it is rejected, so a malformed call can never wipe unrelated TXT records (SPF, DKIM…).
func (p *Provider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var deleted []libdns.Record
	for _, rec := range recs {
		rr := rec.RR()
		if rr.Type != "" && rr.Type != "TXT" {
			continue // not ours to manage
		}
		if rr.Data == "" {
			return deleted, errors.New("zoneee: refusing to delete TXT records without an exact value")
		}
		apiZone, fqdn := names(zone, rr.Name)

		var existing []txtRecord
		if err := p.do(ctx, http.MethodGet, txtPath(apiZone), nil, &existing); err != nil {
			return deleted, err
		}
		for _, e := range existing {
			if !strings.EqualFold(strings.TrimSuffix(e.Name, "."), fqdn) || e.Destination != rr.Data {
				continue
			}
			if err := p.do(ctx, http.MethodDelete,
				txtPath(apiZone)+"/"+url.PathEscape(e.ID), nil, nil); err != nil {
				return deleted, err
			}
			deleted = append(deleted, rec)
		}
	}
	return deleted, nil
}

var (
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
