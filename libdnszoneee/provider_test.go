package libdnszoneee

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/libdns/libdns"
)

func TestAppendThenDelete(t *testing.T) {
	var (
		mu    sync.Mutex
		store = []txtRecord{{ID: "spf", Name: "_acme-challenge.example.com", Destination: "v=spf1 -all"}}
		next  = 1
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, k, ok := r.BasicAuth(); !ok || u != "u" || k != "k" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		const base = "/example.com/txt"
		switch {
		case r.Method == http.MethodPost && r.URL.Path == base:
			var rec txtRecord
			_ = json.NewDecoder(r.Body).Decode(&rec)
			rec.ID = fmt.Sprint(next)
			next++
			store = append(store, rec)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode([]txtRecord{rec})
		case r.Method == http.MethodGet && r.URL.Path == base:
			_ = json.NewEncoder(w).Encode(store)
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, base+"/"):
			id := strings.TrimPrefix(r.URL.Path, base+"/")
			for i, rec := range store {
				if rec.ID == id {
					store = append(store[:i], store[i+1:]...)
					break
				}
			}
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	p := &Provider{Username: "u", APIKey: "k", baseURL: srv.URL + "/"}
	ctx := context.Background()
	rec := libdns.TXT{Name: "_acme-challenge", Text: "token123"}

	if _, err := p.AppendRecords(ctx, "example.com.", []libdns.Record{rec}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.DeleteRecords(ctx, "example.com.", []libdns.Record{rec}); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(store) != 1 || store[0].ID != "spf" {
		t.Fatalf("expected only the unrelated SPF record to remain, got %+v", store)
	}
}

func TestDeleteRefusesEmptyValue(t *testing.T) {
	p := &Provider{Username: "u", APIKey: "k", baseURL: "http://unused/"}
	_, err := p.DeleteRecords(context.Background(), "example.com.",
		[]libdns.Record{libdns.RR{Name: "_acme-challenge", Type: "TXT"}})
	if err == nil {
		t.Fatal("expected refusal for empty Data")
	}
}
