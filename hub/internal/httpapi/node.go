// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/domain"
	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/fleet"
)

// CLIVersionHeader carries the node agent version (§4.4).
const CLIVersionHeader = "X-TrueSignal-CLI-Version"

// NodeStore is the persistence the node API needs.
type NodeStore interface {
	Node(ctx context.Context, id string) (*domain.Node, error)
	SetNodeRevisions(ctx context.Context, id, desired, applied string) error
}

// HubEventRaiser raises Hub events through the event pipeline.
type HubEventRaiser interface {
	RaiseHubEvent(ctx context.Context, nodeID, sensorID, trigger string, sev domain.Severity, source, target string, details map[string]any) (*domain.Event, error)
}

// NodeAPI serves the node agent CLI (node-key authenticated).
type NodeAPI struct {
	Ingest   *Ingest // shares node-key auth and rate limiting
	Fleet    *fleet.Service
	Store    NodeStore
	Raiser   HubEventRaiser // raises node_apply_failed
	HubMajor int

	mu         sync.Mutex
	lastFailed map[string]string // node id -> revision already alerted
}

// Register mounts the routes.
func (n *NodeAPI) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v3/node/identity", n.cli(n.Ingest.authenticated(n.identity)))
	mux.HandleFunc("GET /v3/node/compose", n.cli(n.Ingest.authenticated(n.compose)))
	mux.HandleFunc("POST /v3/node/applied", n.cli(n.Ingest.authenticated(n.applied)))
}

var semverMajorRE = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$`)

// cli enforces the CLI/Hub major-version rule before authentication.
func (n *NodeAPI) cli(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		v := strings.TrimSpace(r.Header.Get(CLIVersionHeader))
		major := -1
		if semverMajorRE.MatchString(v) {
			major, _ = strconv.Atoi(v[:strings.IndexByte(v, '.')])
		}
		if major != n.HubMajor {
			writeJSON(w, http.StatusUpgradeRequired, map[string]any{
				"ok": false, "error": "version_mismatch", "required_major": n.HubMajor,
				"message": "this Hub requires a truesignal CLI with major version " + strconv.Itoa(n.HubMajor),
			})
			return
		}
		next(w, r)
	}
}

func (n *NodeAPI) identity(w http.ResponseWriter, r *http.Request, nodeID string) {
	node, err := n.Store.Node(r.Context(), nodeID)
	if err != nil {
		Fail(w, http.StatusUnauthorized, CodeUnauthorized, "node not found")
		return
	}
	OK(w, map[string]any{"node_id": node.ID, "alias": node.Alias, "tags": node.Tags,
		"desired_revision": node.DesiredRevision, "applied_revision": node.AppliedRevision,
		"hub_version": n.Ingest.Version.Version})
}

func (n *NodeAPI) compose(w http.ResponseWriter, r *http.Request, nodeID string) {
	rd, err := n.Fleet.Deploy(r.Context(), nodeID)
	if err != nil {
		var re *fleet.RenderError
		switch {
		case errors.As(err, &re):
			writeJSON(w, re.Status, map[string]any{"ok": false, "error": re.Code, "message": re.Message, "sensor_id": re.SensorID})
		case errors.Is(err, fleet.ErrCompilerUnavailable):
			Fail(w, http.StatusServiceUnavailable, "compose_unavailable", "the Hub cannot render compose files")
		default:
			n.Ingest.Log.Error("deploy render failed", "node_id", nodeID, "error", err.Error())
			Fail(w, http.StatusInternalServerError, CodeInternal, "render failed")
		}
		return
	}
	OK(w, map[string]any{"revision": rd.Revision, "compose": json.RawMessage(rd.Compose), "warnings": nonNilStrings(rd.Warnings)})
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

var revisionRE = regexp.MustCompile(`^rev_[0-9a-f]{8}$`)

// alertApplyFailed raises node_apply_failed once per node and revision.
func (n *NodeAPI) alertApplyFailed(ctx context.Context, nodeID, revision, result, msg string) error {
	if n.Raiser == nil {
		return nil
	}
	n.mu.Lock()
	if n.lastFailed == nil {
		n.lastFailed = map[string]string{}
	}
	if n.lastFailed[nodeID] == revision {
		n.mu.Unlock()
		return nil
	}
	n.lastFailed[nodeID] = revision
	n.mu.Unlock()
	desired := ""
	if node, err := n.Store.Node(ctx, nodeID); err == nil {
		desired = node.DesiredRevision
	}
	_, err := n.Raiser.RaiseHubEvent(ctx, nodeID, "", domain.TriggerNodeApplyFailed, domain.SeverityHigh,
		domain.HubSource, nodeID, map[string]any{
			"revision": revision, "desired_revision": desired, "result": result, "message": msg,
		})
	return err
}

func (n *NodeAPI) applied(w http.ResponseWriter, r *http.Request, nodeID string) {
	var req struct {
		Revision string `json:"revision"`
		Result   string `json:"result"` // applied | unchanged | rolled_back | failed
		Message  string `json:"message"`
	}
	if err := DecodeStrict(w, r, 64<<10, &req); err != nil {
		FailDecode(w, err)
		return
	}
	if !revisionRE.MatchString(req.Revision) {
		Fail(w, http.StatusBadRequest, CodeInvalid, "revision must be rev_ + 8 hex")
		return
	}
	switch req.Result {
	case "applied", "unchanged":
		if err := n.Store.SetNodeRevisions(r.Context(), nodeID, "", req.Revision); err != nil {
			Fail(w, http.StatusInternalServerError, CodeInternal, "could not record the revision")
			return
		}
		n.mu.Lock()
		delete(n.lastFailed, nodeID) // a later failure alerts again
		n.mu.Unlock()
	case "rolled_back", "failed":
		// The decoys of this node may not be running as configured.
		msg := strings.ToValidUTF8(req.Message, "?")
		if len(msg) > 512 {
			msg = strings.ToValidUTF8(msg[:512], "")
		}
		n.Ingest.Log.Warn("node failed to apply its desired revision", "node_id", nodeID, "revision", req.Revision,
			"result", req.Result, "message", msg)
		if err := n.alertApplyFailed(r.Context(), nodeID, req.Revision, req.Result, msg); err != nil {
			n.Ingest.Log.Error("raising node_apply_failed failed", "node_id", nodeID, "error", err.Error())
		}
	default:
		Fail(w, http.StatusBadRequest, CodeInvalid, "result must be applied, unchanged, rolled_back or failed")
		return
	}
	OK(w, nil)
}
