// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

package manifest

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// ListSeparator separates list items in a config value.
const ListSeparator = ","

// MaxListItems bounds list values when the manifest sets no max_items.
const MaxListItems = 64

// SplitList splits a list value into trimmed, non-empty items.
func SplitList(v string) []string {
	var out []string
	for _, it := range strings.Split(v, ListSeparator) {
		if it = strings.TrimSpace(it); it != "" {
			out = append(out, it)
		}
	}
	return out
}

// CheckValue validates a user value against its declaration.
func CheckValue(k *ConfigKey, v string) error {
	if len(v) > 4096 {
		return fmt.Errorf("value too long")
	}
	for _, r := range v {
		if unicode.IsControl(r) {
			return fmt.Errorf("value contains control characters")
		}
	}
	if k.Type == "list" {
		items := SplitList(v)
		max := MaxListItems
		if k.Validation != nil && k.Validation.MaxItems > 0 {
			max = k.Validation.MaxItems
		}
		if len(items) > max {
			return fmt.Errorf("at most %d items", max)
		}
		item := *k
		item.Type, item.ItemType = k.ItemType, ""
		for _, it := range items {
			if err := CheckValue(&item, it); err != nil {
				return fmt.Errorf("item %q: %w", trunc(it), err)
			}
		}
		return nil
	}
	val := k.Validation
	switch k.Type {
	case "bool":
		if v != "true" && v != "false" {
			return fmt.Errorf("must be true or false")
		}
	case "int", "port":
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return fmt.Errorf("must be an integer")
		}
		if k.Type == "port" && (n < 1 || n > 65535) {
			return fmt.Errorf("port must be 1..65535")
		}
		if val != nil && val.Min != nil && n < *val.Min {
			return fmt.Errorf("must be ≥ %d", *val.Min)
		}
		if val != nil && val.Max != nil && n > *val.Max {
			return fmt.Errorf("must be ≤ %d", *val.Max)
		}
	case "enum":
		ok := false
		if val != nil {
			for _, e := range val.Enum {
				ok = ok || e == v
			}
		}
		if !ok {
			return fmt.Errorf("must be one of the declared values")
		}
	case "path":
		if err := CheckPathSyntax(v); err != nil {
			return err
		}
	case "string":
	}
	if val != nil {
		if val.MaxLen > 0 && len(v) > val.MaxLen {
			return fmt.Errorf("at most %d bytes", val.MaxLen)
		}
		if val.Pattern != "" && k.Type != "enum" {
			re, err := regexp.Compile("^(?:" + val.Pattern + ")$")
			if err != nil || !re.MatchString(v) {
				return fmt.Errorf("does not match the declared pattern")
			}
		}
	}
	return nil
}

// ForbiddenMountPrefixes may never be bind-mounted, nor anything inside
// them (§6.12 rule 4).
var ForbiddenMountPrefixes = []string{
	"/run", "/var/run", "/proc", "/sys", "/dev", "/boot", "/etc", "/root", "/usr", "/bin", "/sbin",
	"/lib", "/lib32", "/lib64", "/libx32", "/var/lib/docker", "/var/lib/containerd", "/var/lib/kubelet",
}

// CheckPathSyntax requires an absolute, normalised path without
// interpolation, control characters or characters meaningful to compose.
func CheckPathSyntax(p string) error {
	if !strings.HasPrefix(p, "/") {
		return &RuleError{Code: "mount_not_allowed", Msg: fmt.Sprintf("path %q must be absolute", trunc(p))}
	}
	if path.Clean(p) != p || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") {
		return &RuleError{Code: "mount_not_allowed", Msg: fmt.Sprintf("path %q must be normalised (no .., //, trailing /)", trunc(p))}
	}
	if HasInterpolation(p) {
		return &RuleError{Code: "interpolation", Msg: fmt.Sprintf("path %q must not contain $ or {{", trunc(p))}
	}
	for _, r := range p {
		if unicode.IsControl(r) || r == ',' || r == ':' {
			return &RuleError{Code: "mount_not_allowed", Msg: fmt.Sprintf("path %q contains a forbidden character", trunc(p))}
		}
	}
	if len(p) > 1024 {
		return &RuleError{Code: "mount_not_allowed", Msg: "path too long"}
	}
	return nil
}

// CheckMountSource applies §6.12 rule 4 to a bind-mount source.
func CheckMountSource(p string) error {
	if err := CheckPathSyntax(p); err != nil {
		return err
	}
	if p == "/" {
		return &RuleError{Code: "mount_not_allowed", Msg: "cannot mount /"}
	}
	for _, f := range ForbiddenMountPrefixes {
		if p == f || strings.HasPrefix(p, f+"/") {
			return &RuleError{Code: "mount_not_allowed", Msg: fmt.Sprintf("cannot mount %q: inside %s", trunc(p), f)}
		}
		// An ancestor (e.g. /var) would expose the forbidden tree as well.
		if strings.HasPrefix(f, p+"/") {
			return &RuleError{Code: "mount_not_allowed", Msg: fmt.Sprintf("cannot mount %q: contains %s", trunc(p), f)}
		}
	}
	return nil
}
