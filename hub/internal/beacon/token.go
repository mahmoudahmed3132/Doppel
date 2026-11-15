// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package beacon creates callback tokens (DNS names, web bugs, kubeconfig
// files) and resolves the ones Token Receivers report.
//
// A token is 24 lowercase base32 characters: 10 random bytes and a 5-byte
// tag, HMAC-SHA256(receiverKey, "truesignal-beacon-v1:" || random), where
// receiverKey is the TS_BEACON_KEY string the Hub injects into every Token
// Receiver (compose: hex HMAC-SHA256(beacon master key, BeaconKeyLabel)).
// Receivers check the tag offline, so names a scanner invents under the zone
// never become events. The master key never leaves the Hub; the receiver key
// is the same for every receiver, so a beacon keeps working when its receiver
// is redeployed, relinked or doubled for DNS redundancy.
//
// Imported from TrueSignal (see PROVENANCE.md): the token format and the
// artefact renderer are that module's; storage and keys are the base's.
package beacon

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"regexp"
	"strings"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

// Beacon types. The API takes kebab-case type names (catalogue-name rule),
// so web bugs are "web-bug".
const (
	TypeDNS        = "dns"
	TypeWebBug     = "web-bug"
	TypeKubeconfig = "kubeconfig"
)

var types = map[string]bool{TypeDNS: true, TypeWebBug: true, TypeKubeconfig: true}

const (
	tokenRandom = 10
	tokenTag    = 5
	tokenDomain = "truesignal-beacon-v1:"
	// TokenLen is the length of every token.
	TokenLen = 24
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func tag(key string, random []byte) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(tokenDomain))
	mac.Write(random)
	return mac.Sum(nil)[:tokenTag]
}

// makeToken builds a token from random bytes under key.
func makeToken(key string, random []byte) string {
	return strings.ToLower(b32.EncodeToString(append(append([]byte{}, random...), tag(key, random)...)))
}

// ValidToken reports whether token carries a correct tag under key (what a
// Token Receiver checks before it reports anything).
func ValidToken(key, token string) bool {
	raw, err := b32.DecodeString(strings.ToUpper(token))
	if err != nil || len(raw) != tokenRandom+tokenTag {
		return false
	}
	return hmac.Equal(raw[tokenRandom:], tag(key, raw[:tokenRandom]))
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slug(s, fallback string) string {
	s = strings.Trim(slugRe.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(s) > 40 {
		s = strings.Trim(s[:40], "-")
	}
	if s == "" {
		return fallback
	}
	return s
}

// derived is a stable pseudo-random string for the artefact's decoration
// (fake credentials), so downloading it twice gives the same file.
func derived(token, purpose string, n int) string {
	sum := sha256.Sum256([]byte(purpose + ":" + token))
	return base64.RawURLEncoding.EncodeToString(sum[:])[:n]
}

// clusterNames are neutral kubeconfig cluster names. The beacon name says
// where it is planted, so it must never appear in the artefact itself.
var clusterNames = []string{"prod-eks", "prod-gke", "k8s-prod", "prod-cluster", "platform-prod", "prod-aks"}

// Render produces the artefact for b. It is deterministic. Its content is
// what gets planted, so it carries nothing that identifies the product or
// the operator's note (the beacon name): only the filename, which stays with
// the operator, is derived from the name.
func Render(b ported.Beacon) ported.BeaconArtefact {
	host := b.Token + "." + b.Domain
	switch b.Type {
	case TypeWebBug:
		url := "http://" + b.Domain + "/static/" + b.Token + ".gif"
		return ported.BeaconArtefact{
			Filename:    slug(b.Name, "web-bug") + "-web-bug.html",
			ContentType: "text/html",
			Body:        []byte("<img src=\"" + url + "\" width=\"1\" height=\"1\" alt=\"\" style=\"display:none\">\n"),
		}
	case TypeKubeconfig:
		// No certificate-authority-data: kubectl would reject fake CA data
		// before it resolves the server, and the lookup is the beacon.
		sum := sha256.Sum256([]byte("cluster:" + b.Token))
		cluster := clusterNames[int(sum[0])%len(clusterNames)]
		return ported.BeaconArtefact{
			Filename:    "kubeconfig-" + slug(b.Name, "beacon") + ".yaml",
			ContentType: "application/yaml",
			Body: []byte("apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    insecure-skip-tls-verify: true\n" +
				"    server: https://" + host + ":6443\n  name: " + cluster + "\ncontexts:\n- context:\n    cluster: " + cluster + "\n    user: " + cluster + "-admin\n" +
				"  name: " + cluster + "\ncurrent-context: " + cluster + "\npreferences: {}\nusers:\n- name: " + cluster + "-admin\n  user:\n" +
				"    token: " + derived(b.Token, "user", 43) + "\n"),
		}
	default:
		return ported.BeaconArtefact{
			Filename:    slug(b.Name, "dns") + "-dns-token.txt",
			ContentType: "text/plain",
			Body:        []byte(host + "\n"),
		}
	}
}
