// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package discover

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type fakeRunner map[string]string

func (f fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	out, ok := f[name+" "+strings.Join(args, " ")]
	if !ok {
		return nil, errors.New("exit status 1")
	}
	return []byte(out), nil
}

func TestScanCommands(t *testing.T) {
	r := fakeRunner{
		"lsof -nP -iTCP -sTCP:LISTEN -F pcn": "p101\ncsshd\nf3\nn*:22\nf4\nn[::]:22\np202\ncpostgres\nf5\nn127.0.0.1:5432\n",
		"lsof -nP -iUDP -F pcn":              "p303\ncmDNSResponder\nf6\nn*:5353\nf7\nn*:*\np404\ncchrome\nf8\nn10.0.0.2:5000->1.1.1.1:443\n",
		"ps -axo comm=":                      "/usr/sbin/sshd\n/opt/homebrew/bin/postgres\nlaunchd\n/usr/sbin/sshd\n",
	}
	h, err := ScanCommands(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	want := []Socket{{"tcp", 22, "sshd"}, {"udp", 5353, "mDNSResponder"}, {"tcp", 5432, "postgres"}}
	if !reflect.DeepEqual(h.Sockets, want) {
		t.Fatalf("sockets %v", h.Sockets)
	}
	if !reflect.DeepEqual(h.Processes, []string{"launchd", "postgres", "sshd"}) {
		t.Fatalf("processes %v", h.Processes)
	}
	if h.Source() != LsofSource || !h.Listening(5432) {
		t.Fatal("source/listening")
	}
	// No lsof/ps at all: an empty, valid snapshot.
	h, err = ScanCommands(context.Background(), fakeRunner{})
	if err != nil || len(h.Sockets) != 0 || len(h.Processes) != 0 {
		t.Fatalf("%v %v", h, err)
	}
}
