// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package honeytoken

import (
	"reflect"
	"sort"
	"testing"
)

func TestCandidateUsernameForms(t *testing.T) {
	got := candidateUsernames(map[string]any{
		"username":           `CORP\Svc_Backup1a2b`,
		"attempted_username": "svc_etl0000@corp.example",
		"bind_dn":            "CN=svc_build9f9f,OU=Service,DC=corp,DC=example",
		"anonymous_bind_dn":  "",
		"other":              "ignored",
	})
	sort.Strings(got)
	want := []string{"svc_backup1a2b", "svc_build9f9f", "svc_etl0000", "svc_etl0000@corp.example"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestGenerateShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		u, s, err := generate()
		if err != nil || len(u) < 9 || len(s) != 15 || seen[u+s] {
			t.Fatal(u, s, err)
		}
		seen[u+s] = true
	}
}
