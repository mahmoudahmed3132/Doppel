// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package semver

import "testing"

func TestPrecedence(t *testing.T) {
	// SemVer 2.0.0 §11 example chain.
	chain := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.9.0", "1.10.0", "2.0.0"}
	for i := 0; i+1 < len(chain); i++ {
		if !Less(chain[i], chain[i+1]) || Less(chain[i+1], chain[i]) {
			t.Errorf("%s < %s failed", chain[i], chain[i+1])
		}
	}
	if Less("1.0.0", "1.0.0") || Less("bogus", "1.0.0") || Less("1.0.0", "bogus") || Valid("1.0") || Valid("01.0.0") {
		t.Fatal("edge cases")
	}
}
