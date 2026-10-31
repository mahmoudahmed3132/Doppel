// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package main

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Honeytoken is the credential the Hub issues for this canary
// (TS_HONEYTOKEN, JSON {"id","username","secret"}).
type Honeytoken struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Secret   string `json:"secret"`
}

// LureGenerator is the seam for the PORTED lure-content module (§12): it
// produces realistic content for a path, embedding the honeytoken where
// the content type supports it, and classifies paths.
type LureGenerator interface {
	Content(path string, ht Honeytoken) (content []byte, category string, err error)
	Category(path string) string
}

// stubLures is a deliberately plain stand-in until the PORTED module is
// imported. Its content is NOT realistic enough for production lures.
type stubLures struct{}

func (stubLures) Category(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".env", ".ini", ".conf", ".cfg", ".yaml", ".yml", ".json":
		return "config"
	case ".kdbx", ".key", ".pem", ".ppk":
		return "secret"
	case ".xlsx", ".csv", ".docx", ".pdf":
		return "document"
	}
	if strings.Contains(strings.ToLower(path), "credential") || strings.Contains(strings.ToLower(path), "password") {
		return "credentials"
	}
	return "file"
}

func (s stubLures) Content(path string, ht Honeytoken) ([]byte, string, error) {
	c := fmt.Sprintf("# %s\n# Service account for nightly jobs. Do not share.\nusername=%s\npassword=%s\n",
		filepath.Base(path), ht.Username, ht.Secret)
	return []byte(c), s.Category(path), nil
}
