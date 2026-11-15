// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package signing verifies that sensor manifests were published by this
// project's release pipeline.
//
// CI signs every versioned manifest with Sigstore keyless signing (cosign
// sign-blob): a short-lived Fulcio certificate bound to the GitHub Actions
// identity of the publish workflow at the sensor's release tag, logged in
// Rekor. The Hub verifies the bundle offline against the embedded Sigstore
// public-good trusted root and pins the exact workflow identity, so a manifest
// is accepted only if this repository's publish workflow signed it for that
// sensor and version. A manifest pins its image by digest, so the signature
// covers the image the node will run.
package signing

import (
	"bytes"
	_ "embed"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// publicGoodTrustedRoot is the Sigstore public-good trusted root
// (trusted_root.json from the sigstore/root-signing TUF repository, verified
// through the TUF chain when it was added). Embedded file sha256:
// 6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66
// Refresh it with Hub releases (docs/operations.md "Sigstore trusted root");
// TS_SIGSTORE_TRUSTED_ROOT overrides it at runtime.
//
//go:embed trusted_root.json
var publicGoodTrustedRoot []byte

const (
	// GitHubOIDCIssuer issues the identity tokens of GitHub Actions.
	GitHubOIDCIssuer = "https://token.actions.githubusercontent.com"
	// DefaultSignerRepo is the repository whose publish workflow signs the
	// official registry. TS_MANIFEST_SIGNER_REPO overrides it.
	DefaultSignerRepo = "mahmoudahmed3132/Doppel"

	// publishWorkflow is the workflow that signs sensor manifests (§10).
	publishWorkflow = ".github/workflows/publish-sensor.yml"
)

var (
	repoPattern    = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	namePattern    = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	versionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
)

// Verifier is the Sigstore manifest verifier (the PORTED seam
// ported.ManifestVerifier, see Verify).
type Verifier struct {
	v      *verify.Verifier
	repo   string
	issuer string
}

// TrustedRoot returns the trusted root to use: the file at path when set,
// otherwise the embedded public-good root.
func TrustedRoot(path string) (root.TrustedMaterial, error) {
	data := publicGoodTrustedRoot
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read trusted root: %w", err)
		}
		data = b
	}
	tr, err := root.NewTrustedRootFromJSON(data)
	if err != nil {
		return nil, fmt.Errorf("parse trusted root: %w", err)
	}
	return tr, nil
}

// New builds a verifier that accepts manifests signed by repo's publish
// workflow. Every signature must carry a Fulcio certificate with an embedded
// CT log SCT, a transparency log entry and a verified timestamp (Rekor
// integrated time or a timestamp authority).
func New(tm root.TrustedMaterial, repo string) (*Verifier, error) {
	return newVerifier(tm, repo, GitHubOIDCIssuer, true)
}

// newVerifier lets tests against sigstore-go's virtual CA, which issues no
// SCTs, drop the SCT requirement; production always requires it.
func newVerifier(tm root.TrustedMaterial, repo, issuer string, requireSCT bool) (*Verifier, error) {
	if !repoPattern.MatchString(repo) {
		return nil, fmt.Errorf("invalid signer repository %q (want owner/name)", repo)
	}
	opts := []verify.VerifierOption{verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)}
	if requireSCT {
		opts = append(opts, verify.WithSignedCertificateTimestamps(1))
	}
	v, err := verify.NewVerifier(tm, opts...)
	if err != nil {
		return nil, err
	}
	return &Verifier{v: v, repo: repo, issuer: issuer}, nil
}

// Identity is the certificate SAN the publish workflow has when it releases
// sensorName at version: the workflow file at the sensor's release tag.
func (v *Verifier) Identity(sensorName, version string) string {
	return fmt.Sprintf("https://github.com/%s/%s@refs/tags/sensor/%s/v%s", v.repo, publishWorkflow, sensorName, version)
}

// VerifyManifest checks that bundleJSON is a valid Sigstore signature over
// manifest by this repository's publish workflow for exactly this sensor and
// version (so a signed manifest cannot be replayed under another name or
// version).
func (v *Verifier) VerifyManifest(sensorName, version string, manifest, bundleJSON []byte) error {
	if len(bundleJSON) == 0 {
		return errors.New("manifest is not signed (no Sigstore bundle)")
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return fmt.Errorf("invalid Sigstore bundle: %w", err)
	}
	return v.verifyEntity(&b, sensorName, version, manifest)
}

func (v *Verifier) verifyEntity(entity verify.SignedEntity, sensorName, version string, manifest []byte) error {
	if !namePattern.MatchString(sensorName) || !versionPattern.MatchString(version) {
		return fmt.Errorf("invalid sensor %q version %q", sensorName, version)
	}
	id, err := verify.NewShortCertificateIdentity(v.issuer, "", v.Identity(sensorName, version), "")
	if err != nil {
		return err
	}
	if _, err := v.v.Verify(entity, verify.NewPolicy(verify.WithArtifact(bytes.NewReader(manifest)), verify.WithCertificateIdentity(id))); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// Verify implements ported.ManifestVerifier, whose argument order differs
// from VerifyManifest.
func (v *Verifier) Verify(manifest, bundleJSON []byte, sensorName, version string) error {
	return v.VerifyManifest(sensorName, version, manifest, bundleJSON)
}

var _ ported.ManifestVerifier = (*Verifier)(nil)
