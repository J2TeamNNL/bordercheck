package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/ptrinh/bordercheck/internal/update"
)

// runVerify checks downloaded release files the way self-update does: that
// SHA256SUMS is signed by the trusted key and that each file matches its line.
// The installers use it when no other ed25519 verifier is at hand. A binary
// vouching for its own release proves little on its own; see docs/install.md,
// "What the install script proves".
func runVerify(args []string) int {
	fs := flag.NewFlagSet("bordercheck verify", flag.ContinueOnError)
	key := fs.String("key", "", "base64 ed25519 public key; default: the official release key built into this binary")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, "Usage: bordercheck verify [-key base64] SHA256SUMS SHA256SUMS.sig [file...]\n\n"+
			"Checks the signature on SHA256SUMS, then that each file matches its SHA256SUMS line.\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() < 2 {
		fs.Usage()
		return 2
	}
	if err := verifyRelease(*key, fs.Arg(0), fs.Arg(1), fs.Args()[2:]); err != nil {
		return fail(err)
	}
	fmt.Println("OK: SHA256SUMS is signed by the trusted key and every file matches it.")
	return 0
}

func verifyRelease(key, sumsPath, sigPath string, files []string) error {
	sums, err := os.ReadFile(sumsPath)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(sigPath)
	if err != nil {
		return err
	}
	if err := update.VerifySums(sums, sig, key); err != nil {
		return err
	}
	for _, f := range files {
		want, err := update.SumFor(sums, filepath.Base(f))
		if err != nil {
			return err
		}
		data, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if got := sha256.Sum256(data); !bytes.Equal(got[:], want) {
			return errors.New(filepath.Base(f) + " does not match its SHA256SUMS line")
		}
	}
	return nil
}
