package zoneee

import (
	"errors"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/jooseplainvoo/caddy-dns-zoneee/libdnszoneee"
)

type Provider struct{ *libdnszoneee.Provider }

func init() { caddy.RegisterModule(Provider{}) }

func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.zoneee",
		New: func() caddy.Module { return &Provider{new(libdnszoneee.Provider)} },
	}
}

// Provision expands {env.*} placeholders and fails fast on missing credentials,
// so a misconfiguration surfaces at startup, not 60 days later at renewal.
func (p *Provider) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	p.Provider.Username = repl.ReplaceAll(p.Provider.Username, "")
	p.Provider.APIKey = repl.ReplaceAll(p.Provider.APIKey, "")
	if p.Provider.Username == "" || p.Provider.APIKey == "" {
		return errors.New("zoneee: username and api_key are required (is the environment variable set?)")
	}
	return nil
}

//	dns zoneee {
//	    username <user>
//	    api_key  <key>
//	}
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume "zoneee"
	if d.NextArg() {
		return d.ArgErr() // no inline arguments
	}
	for d.NextBlock(0) {
		switch d.Val() {
		case "username":
			if !d.AllArgs(&p.Provider.Username) {
				return d.ArgErr()
			}
		case "api_key":
			if !d.AllArgs(&p.Provider.APIKey) {
				return d.ArgErr()
			}
		default:
			return d.Errf("unrecognized subdirective %q", d.Val())
		}
	}
	return nil
}

var (
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
)
