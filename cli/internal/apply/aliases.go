// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package apply

import (
	"runtime"
	"strings"
)

// darwinAliases are macOS's fixed, root-owned system symlinks. A bind source
// under one of them legitimately resolves to its /private target; any other
// symbolic link on the path is still refused.
var darwinAliases = map[string]string{
	"/etc": "/private/etc",
	"/tmp": "/private/tmp",
	"/var": "/private/var",
}

// systemAliases is the alias table for this OS (empty on Linux).
var systemAliases = func() map[string]string {
	if runtime.GOOS == "darwin" {
		return darwinAliases
	}
	return nil
}()

// realiasPath maps p from one side of an alias table to the other: with
// forward=true "/var/x" -> "/private/var/x"; otherwise the reverse.
func realiasPath(aliases map[string]string, p string, forward bool) string {
	for alias, target := range aliases {
		from, to := alias, target
		if !forward {
			from, to = target, alias
		}
		if p == from || strings.HasPrefix(p, from+"/") {
			return to + p[len(from):]
		}
	}
	return p
}
