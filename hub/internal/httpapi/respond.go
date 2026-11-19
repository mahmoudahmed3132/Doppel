// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Package httpapi contains the Hub's HTTP handlers. Handlers parse,
// validate and serialise only; business logic lives in services.
package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Error codes shared by handlers.
const (
	CodeInvalidJSON  = "invalid_json"
	CodeUnknownField = "unknown_field"
	CodeTooLarge     = "body_too_large"
	CodeUnauthorized = "unauthorized"
	CodeRateLimited  = "rate_limited"
	CodeNotFound     = "not_found"
	CodeInternal     = "internal_error"
	CodeInvalid      = "invalid_request"
)

// writeJSON writes v with status. v must marshal; failures are programming
// errors and produce a 500 envelope.
func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		status = http.StatusInternalServerError
		buf.Reset()
		buf.WriteString(`{"ok":false,"error":"internal_error","message":"response encoding failed"}` + "\n")
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

// OK writes {"ok": true, ...fields}.
func OK(w http.ResponseWriter, fields map[string]any) {
	out := map[string]any{"ok": true}
	for k, v := range fields {
		out[k] = v
	}
	writeJSON(w, http.StatusOK, out)
}

// Fail writes the error envelope.
func Fail(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"ok": false, "error": code, "message": message})
}

// decodeError classifies a strict-decoding failure.
type decodeError struct {
	status int
	code   string
	msg    string
}

func (e *decodeError) Error() string { return e.msg }

// DecodeStrict reads at most limit bytes from r.Body and decodes exactly one
// JSON value into dst, refusing unknown fields and trailing data.
func DecodeStrict(w http.ResponseWriter, r *http.Request, limit int64, dst any) error {
	body := http.MaxBytesReader(w, r.Body, limit)
	data, err := io.ReadAll(body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return &decodeError{http.StatusRequestEntityTooLarge, CodeTooLarge, fmt.Sprintf("request body exceeds %d bytes", limit)}
		}
		return &decodeError{http.StatusBadRequest, CodeInvalidJSON, "unreadable body"}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		if isUnknownField(err) {
			return &decodeError{http.StatusBadRequest, CodeUnknownField, err.Error()}
		}
		return &decodeError{http.StatusBadRequest, CodeInvalidJSON, "malformed JSON"}
	}
	if dec.More() {
		return &decodeError{http.StatusBadRequest, CodeInvalidJSON, "trailing data after JSON value"}
	}
	return nil
}

func isUnknownField(err error) bool {
	// encoding/json reports unknown fields only through this message.
	return err != nil && bytes.HasPrefix([]byte(err.Error()), []byte("json: unknown field "))
}

// FailDecode writes the envelope for a DecodeStrict error.
func FailDecode(w http.ResponseWriter, err error) {
	var de *decodeError
	if errors.As(err, &de) {
		Fail(w, de.status, de.code, de.msg)
		return
	}
	Fail(w, http.StatusBadRequest, CodeInvalidJSON, "malformed JSON")
}
