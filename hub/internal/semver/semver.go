// Copyright (c) 2026 <TrueSignal Deception>. All rights reserved.

// Package semver parses and orders x.y.z[-pre] versions (SemVer 2.0.0
// precedence; build metadata is not accepted).
package semver

import (
	"regexp"
	"strconv"
	"strings"
)

var re = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$`)

// Valid reports whether v is a supported version.
func Valid(v string) bool { return re.MatchString(v) }

type version struct {
	n   [3]uint64
	pre []string
}

func parse(v string) (*version, bool) {
	m := re.FindStringSubmatch(v)
	if m == nil {
		return nil, false
	}
	var out version
	for i := 0; i < 3; i++ {
		n, err := strconv.ParseUint(m[i+1], 10, 64)
		if err != nil {
			return nil, false
		}
		out.n[i] = n
	}
	if m[4] != "" {
		out.pre = strings.Split(m[4][1:], ".")
	}
	return &out, true
}

// Less reports a < b. Invalid versions are never less than anything.
func Less(a, b string) bool { return Compare(a, b) < 0 }

// Compare returns -1, 0 or 1; invalid versions compare equal to everything.
func Compare(a, b string) int {
	pa, okA := parse(a)
	pb, okB := parse(b)
	if !okA || !okB {
		return 0
	}
	for i := 0; i < 3; i++ {
		if pa.n[i] != pb.n[i] {
			if pa.n[i] < pb.n[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(pa.pre) == 0 && len(pb.pre) == 0:
		return 0
	case len(pa.pre) == 0:
		return 1
	case len(pb.pre) == 0:
		return -1
	}
	for i := 0; i < len(pa.pre) && i < len(pb.pre); i++ {
		if c := compareIdent(pa.pre[i], pb.pre[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(pa.pre) < len(pb.pre):
		return -1
	case len(pa.pre) > len(pb.pre):
		return 1
	}
	return 0
}

// compareIdent orders pre-release identifiers: numeric ones numerically and
// below alphanumeric ones, which compare as ASCII strings.
func compareIdent(a, b string) int {
	na, errA := strconv.ParseUint(a, 10, 64)
	nb, errB := strconv.ParseUint(b, 10, 64)
	switch {
	case errA == nil && errB == nil:
		switch {
		case na < nb:
			return -1
		case na > nb:
			return 1
		}
		return 0
	case errA == nil:
		return -1
	case errB == nil:
		return 1
	}
	return strings.Compare(a, b)
}
