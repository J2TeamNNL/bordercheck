// Command sign signs release checksums for bordercheck's self-update.
//
//	go run ./scripts/sign -keygen            private key (base64) on stdout, public key on stderr
//	go run ./scripts/sign dist/SHA256SUMS    writes dist/SHA256SUMS.sig with $BORDERCHECK_SIGNING_KEY
//
// Keep the private key out of files: pipe -keygen into a secret store, and
// give it to the release workflow as the BORDERCHECK_SIGNING_KEY secret. The
// public key goes in internal/update.OfficialKey.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		os.Exit(1)
	}
}

func run() error {
	keygen := flag.Bool("keygen", false, "generate a key pair")
	flag.Parse()
	if *keygen {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(priv.Seed()))
		fmt.Fprintln(os.Stderr, "public key:", base64.StdEncoding.EncodeToString(pub))
		return nil
	}
	if flag.NArg() != 1 {
		return errors.New("usage: sign FILE (with BORDERCHECK_SIGNING_KEY set) | sign -keygen")
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(os.Getenv("BORDERCHECK_SIGNING_KEY")))
	if err != nil || len(seed) != ed25519.SeedSize {
		return errors.New("BORDERCHECK_SIGNING_KEY must be the base64 key from -keygen")
	}
	data, err := os.ReadFile(flag.Arg(0))
	if err != nil {
		return err
	}
	sig := ed25519.Sign(ed25519.NewKeyFromSeed(seed), data)
	return os.WriteFile(flag.Arg(0)+".sig", []byte(base64.StdEncoding.EncodeToString(sig)+"\n"), 0o644)
}
