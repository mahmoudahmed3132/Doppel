// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package signing

import (
	"os"
	"strings"
	"testing"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const testIssuer = "https://token.actions.githubusercontent.com"

func virtual(t *testing.T) (*ca.VirtualSigstore, *Verifier) {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	v, err := newVerifier(vs, DefaultSignerRepo, testIssuer, false)
	if err != nil {
		t.Fatal(err)
	}
	return vs, v
}

func TestIdentityPinsRepoWorkflowAndTag(t *testing.T) {
	_, v := virtual(t)
	want := "https://github.com/mahmoudahmed3132/TrueSignal-Rewrite/.github/workflows/publish-sensor.yml@refs/tags/sensor/tcp-tarpit/v2.0.3"
	if got := v.Identity("tcp-tarpit", "2.0.3"); got != want {
		t.Fatalf("identity %s", got)
	}
}

func TestVerifyManifest(t *testing.T) {
	vs, v := virtual(t)
	manifest := []byte(`{"id":"ts-sensor-tcp-tarpit","version":"2.0.3"}`)
	good, err := vs.Sign(v.Identity("tcp-tarpit", "2.0.3"), testIssuer, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.verifyEntity(good, "tcp-tarpit", "2.0.3", manifest); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	cases := map[string]func() error{
		"tampered manifest": func() error {
			return v.verifyEntity(good, "tcp-tarpit", "2.0.3", []byte(`{"id":"ts-sensor-tcp-tarpit","version":"2.0.3","x":1}`))
		},
		"replayed under another version": func() error {
			return v.verifyEntity(good, "tcp-tarpit", "2.0.4", manifest)
		},
		"replayed under another sensor": func() error {
			return v.verifyEntity(good, "web-router-decoy", "2.0.3", manifest)
		},
		"signed by another repository": func() error {
			e, _ := vs.Sign(strings.Replace(v.Identity("tcp-tarpit", "2.0.3"), DefaultSignerRepo, "attacker/TrueSignal", 1), testIssuer, manifest)
			return v.verifyEntity(e, "tcp-tarpit", "2.0.3", manifest)
		},
		"signed by another workflow": func() error {
			e, _ := vs.Sign(strings.Replace(v.Identity("tcp-tarpit", "2.0.3"), "publish-sensor.yml", "test.yml", 1), testIssuer, manifest)
			return v.verifyEntity(e, "tcp-tarpit", "2.0.3", manifest)
		},
		"signed from a branch, not the tag": func() error {
			e, _ := vs.Sign(strings.Replace(v.Identity("tcp-tarpit", "2.0.3"), "refs/tags/sensor/tcp-tarpit/v2.0.3", "refs/heads/main", 1), testIssuer, manifest)
			return v.verifyEntity(e, "tcp-tarpit", "2.0.3", manifest)
		},
		"other OIDC issuer": func() error {
			e, _ := vs.Sign(v.Identity("tcp-tarpit", "2.0.3"), "https://accounts.google.com", manifest)
			return v.verifyEntity(e, "tcp-tarpit", "2.0.3", manifest)
		},
		"untrusted CA": func() error {
			other, _ := ca.NewVirtualSigstore()
			e, _ := other.Sign(v.Identity("tcp-tarpit", "2.0.3"), testIssuer, manifest)
			return v.verifyEntity(e, "tcp-tarpit", "2.0.3", manifest)
		},
		"path traversal in name": func() error {
			return v.verifyEntity(good, "../tcp-tarpit", "2.0.3", manifest)
		},
	}
	for name, f := range cases {
		if err := f(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestVerifyManifestRejectsMissingOrGarbageBundle(t *testing.T) {
	_, v := virtual(t)
	if err := v.VerifyManifest("tcp-tarpit", "2.0.3", []byte("{}"), nil); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("missing bundle: %v", err)
	}
	if err := v.VerifyManifest("tcp-tarpit", "2.0.3", []byte("{}"), []byte(`{"mediaType":"nope"}`)); err == nil {
		t.Fatal("garbage bundle accepted")
	}
}

// The embedded public-good root and the production verifier options accept a
// real Sigstore public-good signature (sigstore-js release provenance, from
// sigstore-go's test data), including its SCT, Rekor entry and timestamp.
func TestEmbeddedPublicGoodRootVerifiesRealBundle(t *testing.T) {
	tm, err := TrustedRoot("")
	if err != nil {
		t.Fatal(err)
	}
	v, err := New(tm, DefaultSignerRepo)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("testdata/publicgood-provenance.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	id, _ := verify.NewShortCertificateIdentity(GitHubOIDCIssuer, "", "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main", "")
	if _, err := v.v.Verify(&b, verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithCertificateIdentity(id))); err != nil {
		t.Fatalf("real public-good bundle rejected: %v", err)
	}
	// Our pinned identity does not match someone else's valid signature.
	other, _ := verify.NewShortCertificateIdentity(GitHubOIDCIssuer, "", v.Identity("tcp-tarpit", "2.0.3"), "")
	if _, err := v.v.Verify(&b, verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithCertificateIdentity(other))); err == nil {
		t.Fatal("foreign signature accepted under our identity")
	}
}

func TestNewRejectsBadRepo(t *testing.T) {
	tm, _ := TrustedRoot("")
	for _, r := range []string{"", "noslash", "a/b/c", "a/b@refs"} {
		if _, err := New(tm, r); err == nil {
			t.Errorf("%q accepted", r)
		}
	}
}

// published loads a manifest and its bundle exactly as the publish-sensor.yml
// workflow of this repository signed them for the 1.0.0 releases (copied from
// the registry branch).
func published(t *testing.T, name string) (manifest, bundleJSON []byte) {
	t.Helper()
	dir := "testdata/registry/sensors/" + name + "/1.0.0/"
	m, err := os.ReadFile(dir + "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(dir + "manifest.json.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	return m, b
}

var publishedSensors = []string{"file-canary", "icmp-canary", "network-scan-detector", "tcp-tarpit", "web-router-decoy"}

// The production verifier (embedded public-good root, SCT + Rekor + timestamp
// required, this repository's publish-sensor.yml identity) accepts every
// manifest this repository actually published, through the seam.
func TestRealPublishedManifestsVerify(t *testing.T) {
	tm, err := TrustedRoot("")
	if err != nil {
		t.Fatal(err)
	}
	v, err := New(tm, DefaultSignerRepo)
	if err != nil {
		t.Fatal(err)
	}
	var seam ported.ManifestVerifier = v
	for _, n := range publishedSensors {
		m, b := published(t, n)
		if err := seam.Verify(m, b, n, "1.0.0"); err != nil {
			t.Errorf("%s 1.0.0: %v", n, err)
		}
	}
}

// A signature is bound to one sensor, one version, one repository and the
// exact manifest bytes; the seam's argument order is respected.
func TestRealSignatureIsNotTransferable(t *testing.T) {
	tm, _ := TrustedRoot("")
	v, _ := New(tm, DefaultSignerRepo)
	m, b := published(t, "tcp-tarpit")
	otherM, otherB := published(t, "icmp-canary")
	other, _ := New(tm, "someone/else")
	cases := map[string]error{
		"bundle presented for another sensor":    v.Verify(m, b, "icmp-canary", "1.0.0"),
		"bundle presented for another version":   v.Verify(m, b, "tcp-tarpit", "1.0.1"),
		"another sensor's bundle":                v.Verify(m, otherB, "tcp-tarpit", "1.0.0"),
		"another sensor's manifest":              v.Verify(otherM, b, "tcp-tarpit", "1.0.0"),
		"manifest modified by one byte":          v.Verify(append(append([]byte{}, m...), ' '), b, "tcp-tarpit", "1.0.0"),
		"verifier pinned to another repository":  other.Verify(m, b, "tcp-tarpit", "1.0.0"),
		"name and version swapped":               v.Verify(m, b, "1.0.0", "tcp-tarpit"),
		"manifest and bundle swapped":            v.Verify(b, m, "tcp-tarpit", "1.0.0"),
		"pre-release version (plain X.Y.Z only)": v.Verify(m, b, "tcp-tarpit", "1.0.0-rc.1"),
	}
	for name, err := range cases {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTrustedRootOverride(t *testing.T) {
	if _, err := TrustedRoot("testdata/does-not-exist.json"); err == nil {
		t.Fatal("missing override accepted")
	}
	if _, err := TrustedRoot("testdata/registry/index.json"); err == nil {
		t.Fatal("non-root JSON accepted as trusted root")
	}
	if _, err := TrustedRoot("trusted_root.json"); err != nil {
		t.Fatalf("explicit copy of the embedded root rejected: %v", err)
	}
}
