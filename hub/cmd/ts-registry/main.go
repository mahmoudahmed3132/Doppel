// Copyright (c) 2026 TrueSignal Deception. All rights reserved.

// Command ts-registry runs the registry steps of the sensor publish and
// rollback workflows (§10) on a checkout of the registry branch:
//
//	ts-registry fill -in M -out M2 -name N -version V -repository R -tag T -digest D
//	ts-registry published -dir DIR -name N -version V   (exit 0 if published, 3 if not)
//	ts-registry index -dir DIR
//	ts-registry deprecate -dir DIR -name N
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/mahmoudahmed3132/TrueSignal-Rewrite/hub/internal/registrytool"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	in := fs.String("in", "", "source manifest")
	out := fs.String("out", "", "output manifest")
	dir := fs.String("dir", "", "registry checkout")
	name := fs.String("name", "", "sensor name")
	version := fs.String("version", "", "sensor version")
	repo := fs.String("repository", "", "image repository")
	tag := fs.String("tag", "", "image tag")
	digest := fs.String("digest", "", "image digest")
	fs.Parse(os.Args[2:])

	switch os.Args[1] {
	case "fill":
		raw, err := os.ReadFile(*in)
		check(err)
		b, err := registrytool.Fill(raw, registrytool.FillSpec{Name: *name, Version: *version, Repository: *repo, Tag: *tag, Digest: *digest})
		check(err)
		check(os.WriteFile(*out, b, 0o644))
	case "published":
		if registrytool.Published(*dir, *name, *version) {
			fmt.Printf("%s@%s is already published\n", *name, *version)
			return
		}
		os.Exit(3)
	case "index":
		prev, err := registrytool.LoadIndex(*dir)
		check(err)
		ix, err := registrytool.Build(*dir, prev, time.Now())
		check(err)
		check(os.WriteFile(*dir+"/index.json", registrytool.Marshal(ix), 0o644))
		for n, e := range ix.Sensors {
			fmt.Printf("%s: latest %q, versions %v\n", n, e.Latest, registrytool.Versions(e))
		}
	case "deprecate":
		ix, err := registrytool.LoadIndex(*dir)
		check(err)
		v, err := registrytool.Deprecate(ix, *name)
		check(err)
		ix.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
		check(os.WriteFile(*dir+"/index.json", registrytool.Marshal(ix), 0o644))
		fmt.Printf("deprecated %s@%s; latest is now %q\n", *name, v, ix.Sensors[*name].Latest)
	default:
		usage()
	}
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "ts-registry:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ts-registry fill|published|index|deprecate [flags]")
	os.Exit(2)
}
