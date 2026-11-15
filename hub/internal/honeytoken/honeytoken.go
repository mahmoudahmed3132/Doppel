// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package honeytoken links lures to logins. The Hub plants a fabricated
// credential in each File Canary instance's lures and recognises it when an
// attacker later tries it against any service decoy in the fleet.
//
// Passwords are compared by keyed HMAC. Each node's decoys hash captured
// passwords with that node's capture key (TS_CAPTURE_KEY, derived by the Hub
// from its capture master key and the node ID: compose.CaptureKey), so root
// on one node can at most test that node's own captures. The Hub re-derives
// the reporting node's key for each event and compares the HMAC of every
// honeytoken secret under it, which keeps matching fleet-wide. Usernames are
// compared in plaintext, which also covers captures that carry no password.
//
// Imported from TrueSignal (see PROVENANCE.md): token generation and the
// username/password matching are that module's; the store, key and
// inventory plumbing are adapted to ported.HoneytokenService.
package honeytoken

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
)

// hmacHex is the decoys' password HMAC: hex HMAC-SHA256 over the value with
// the node capture key.
func hmacHex(key []byte, value string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

var accountWords = []string{"backup", "deploy", "sqlsync", "reports", "monitor", "etl", "build", "svcdesk"}

func randomString(alphabet string, n int) (string, error) {
	var b strings.Builder
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b.WriteByte(alphabet[idx.Int64()])
	}
	return b.String(), nil
}

func generate() (username, secret string, err error) {
	w, err := rand.Int(rand.Reader, big.NewInt(int64(len(accountWords))))
	if err != nil {
		return "", "", err
	}
	suffix, err := randomString("0123456789abcdef", 4)
	if err != nil {
		return "", "", err
	}
	// Distinctive enough to never collide with a real account, plausible
	// enough to be tried.
	username = "svc_" + accountWords[w.Int64()] + suffix
	body, err := randomString("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789", 14)
	if err != nil {
		return "", "", err
	}
	tail, err := randomString("!#%*+-", 1)
	if err != nil {
		return "", "", err
	}
	return username, body + tail, nil
}

// candidateUsernames extracts account names an event attempted. DOMAIN\user,
// user@realm and the CN/UID of a bind DN all reduce to the bare name.
func candidateUsernames(details map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" && len(v) <= 256 && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for _, k := range []string{"username", "attempted_username", "bind_dn", "anonymous_bind_dn"} {
		raw, ok := details[k].(string)
		if !ok || raw == "" {
			continue
		}
		if strings.Contains(raw, "=") {
			for _, rdn := range strings.Split(raw, ",") {
				name, val, found := strings.Cut(strings.TrimSpace(rdn), "=")
				if found && (strings.EqualFold(name, "cn") || strings.EqualFold(name, "uid")) {
					add(val)
				}
			}
			continue
		}
		name := raw
		if i := strings.LastIndex(name, `\`); i >= 0 {
			name = name[i+1:]
		}
		add(name)
		if user, _, found := strings.Cut(name, "@"); found {
			add(user)
		}
	}
	return out
}

// candidatePasswords returns the password evidence in an event: HMACs
// (`*password_hmac` fields, made with the reporting node's capture key) and
// plaintext captures from plain capture mode.
func candidatePasswords(details map[string]any) (hmacs, plain []string) {
	for k, v := range details {
		str, ok := v.(string)
		if !ok || str == "" {
			continue
		}
		switch {
		case strings.HasSuffix(k, "password_hmac"):
			hmacs = append(hmacs, strings.ToLower(str))
		case k == "password" || k == "attempted_password":
			plain = append(plain, str)
		}
	}
	return hmacs, plain
}
