// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package beacon

import (
	"strings"
	"testing"

	"github.com/mahmoudahmed3132/Doppel/hub/internal/ported"
)

// The token format is shared with the Token Receiver: a fixed vector pins it.
func TestTokenVectorAndTag(t *testing.T) {
	random := []byte("0123456789")
	tok := makeToken("receiver-key", random)
	if len(tok) != TokenLen || tok != strings.ToLower(tok) {
		t.Fatalf("token %q", tok)
	}
	if !ValidToken("receiver-key", tok) || ValidToken("other-key", tok) {
		t.Fatal("tag check")
	}
	flipped := []byte(tok)
	flipped[0] ^= 1
	if ValidToken("receiver-key", string(flipped)) || ValidToken("receiver-key", tok[:23]) {
		t.Fatal("forged token accepted")
	}
	if again := makeToken("receiver-key", random); again != tok {
		t.Fatal("not deterministic")
	}
}

func TestRenderCarriesNothingIdentifying(t *testing.T) {
	b := ported.Beacon{Token: "abcdefghijklmnopqrstuvwx", Domain: "t.example.com", Name: "Finance share \\\\fs01\\finance", Memo: "secret note"}
	for _, typ := range []string{TypeDNS, TypeWebBug, TypeKubeconfig} {
		b.Type = typ
		a := Render(b)
		body := string(a.Body)
		if !strings.Contains(body, b.Token) || strings.Contains(body, "fs01") || strings.Contains(body, "secret") ||
			strings.Contains(strings.ToLower(body), "truesignal") || strings.Contains(strings.ToLower(body), "doppel") {
			t.Fatalf("%s: %q", typ, body)
		}
		if !strings.HasPrefix(a.Filename, "finance-share-fs01-finance") && !strings.HasPrefix(a.Filename, "kubeconfig-finance-share") {
			t.Fatalf("%s filename %q", typ, a.Filename)
		}
		if string(Render(b).Body) != body {
			t.Fatalf("%s not deterministic", typ)
		}
	}
	if !strings.Contains(string(Render(ported.Beacon{Type: TypeKubeconfig, Token: "x", Domain: "d.example"}).Body), "server: https://x.d.example:6443") {
		t.Fatal("kubeconfig server")
	}
}
