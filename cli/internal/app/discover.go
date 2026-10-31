// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package app

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/cli/internal/config"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/cli/internal/discover"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/cli/internal/hub"
)

// adminLogin opens an admin session. Credentials come from
// TS_ADMIN_PASSWORD / TS_ADMIN_MFA_CODE or no-echo prompts; never stored.
func (a *App) adminLogin(ctx context.Context, c *hub.Client) (*hub.Admin, error) {
	pw := a.Getenv("TS_ADMIN_PASSWORD")
	if pw == "" {
		var err error
		if pw, err = a.ReadSecret("Hub admin password: "); err != nil {
			return nil, err
		}
	}
	code := a.Getenv("TS_ADMIN_MFA_CODE")
	adm, err := c.Login(ctx, pw, code)
	if errors.Is(err, hub.ErrMFARequired) && code == "" {
		if code, err = a.ReadSecret("MFA code: "); err != nil {
			return nil, err
		}
		adm, err = c.Login(ctx, pw, code)
	}
	return adm, err
}

type catalogueList struct {
	Sensors []struct {
		Name   string `json:"name"`
		Latest string `json:"latest"`
	} `json:"sensors"`
}

type nodeDetail struct {
	Node struct {
		Sensors []struct {
			ID            string            `json:"id"`
			CatalogueName string            `json:"catalogue_name"`
			Config        map[string]string `json:"config"`
		} `json:"sensors"`
	} `json:"node"`
}

func (a *App) discover(ctx context.Context, args []string) int {
	fs := a.flags("discover")
	yes := fs.Bool("yes", false, "register all proposals without asking")
	noApply := fs.Bool("no-apply", false, "register sensors but do not run apply")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, err := config.Load(a.Paths)
	if err != nil {
		return a.fail(err)
	}
	host, err := discover.Scan(a.ProcRoot)
	if err != nil {
		return a.fail(err)
	}
	a.info("Host: %d listening sockets, %d process names (read from %s; no network probing)", len(host.Sockets), len(host.Processes), a.ProcRoot)

	c, err := a.client(cfg)
	if err != nil {
		return a.fail(err)
	}
	adm, err := a.adminLogin(ctx, c)
	if err != nil {
		return a.fail(fmt.Errorf("admin login: %w", err))
	}
	defer adm.Logout(ctx)

	var cat catalogueList
	if err := adm.Get(ctx, "/api/v3/catalogue", &cat); err != nil {
		return a.fail(err)
	}
	var nd nodeDetail
	if err := adm.Get(ctx, "/api/v3/nodes/"+cfg.NodeID, &nd); err != nil {
		return a.fail(err)
	}
	deployed := map[string]bool{}
	taken := map[int]bool{}
	for _, s := range nd.Node.Sensors {
		deployed[s.CatalogueName] = true
	}

	env := discover.DefaultEnv()
	if a.DiscoverEnv != nil {
		env = *a.DiscoverEnv
	}
	var proposals []discover.Proposal
	for _, s := range cat.Sensors {
		if s.Latest == "" || deployed[s.Name] {
			continue
		}
		var det struct {
			Manifest *discover.Manifest `json:"manifest"`
		}
		if err := adm.Get(ctx, "/api/v3/catalogue/"+url.PathEscape(s.Name)+"/"+url.PathEscape(s.Latest), &det); err != nil || det.Manifest == nil {
			continue
		}
		reasons := discover.Match(det.Manifest, host, env)
		if len(reasons) == 0 {
			continue
		}
		proposals = append(proposals, discover.Propose(det.Manifest, reasons, host, env, taken))
	}
	if len(proposals) == 0 {
		a.ok("no new decoys match this host")
		return 0
	}

	registered := 0
	for _, p := range proposals {
		a.info("\n%s %s (%s)", a.paint("1", p.Display), p.Version, p.Name)
		a.info("  why:    %s", strings.Join(p.Reasons, ", "))
		keys := make([]string, 0, len(p.Config))
		for k := range p.Config {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			a.info("  config: %s=%s", k, p.Config[k])
		}
		if len(p.Missing) > 0 {
			a.warn("%s needs values for %s; configure it in the Hub instead", p.Name, strings.Join(p.Missing, ", "))
			continue
		}
		if !*yes && !a.confirm("  Deploy this decoy?") {
			continue
		}
		var out struct {
			Sensor struct {
				ID string `json:"id"`
			} `json:"sensor"`
		}
		err := adm.Post(ctx, "/api/v3/nodes/"+cfg.NodeID+"/sensors",
			map[string]any{"catalogue_name": p.Name, "version": p.Version, "config": p.Config}, &out)
		if err != nil {
			a.warn("%s: %v", p.Name, err)
			continue
		}
		a.ok("registered %s", out.Sensor.ID)
		registered++
	}
	if registered == 0 {
		a.info("nothing registered")
		return 0
	}
	if *noApply {
		a.info("Run truesignal apply to deploy.")
		return 0
	}
	return a.apply(ctx, nil)
}
