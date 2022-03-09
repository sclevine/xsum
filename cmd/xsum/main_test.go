package main_test

import (
	"bytes"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	main "github.com/sclevine/xsum/cmd/xsum"
)

func TestRun(t *testing.T) {
	defer func(in, out *os.File) {
		os.Stdin = in
		os.Stdout = out
	}(os.Stdin, os.Stdout)

	for _, opts := range []main.OptionsMask{
		{Full: true},
		{Extended: true},
		{Everything: true},
		{Opaque: true},
	} {
		var err error
		os.Stdin, os.Stdout, err = os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			if err := main.Run(&main.Options{
				General: main.OptionsGeneral{
					Algorithm: "sha256",
				},
				Mask: opts,
				Args: main.OptionsArgs{
					Paths: []string{"../.."},
				},
			}); err != nil {
				t.Error(err)
			}
			os.Stdout.Close()
			wg.Done()
		}()
		go func() {
			if err := main.Run(&main.Options{
				General: main.OptionsGeneral{
					Algorithm: "sha256",
					Check:     true,
				},
				Args: main.OptionsArgs{
					Paths: []string{"-"},
				},
			}); err != nil {
				t.Error(err)
			}
			wg.Done()
		}()
		wg.Wait()
	}
}

func TestRun_shasum(t *testing.T) {
	if _, err := exec.LookPath("shasum"); err != nil {
		t.Skip("shasum not present")
	}
	defer func(out, err *os.File) {
		os.Stdout = out
		log.SetOutput(err)
	}(os.Stdout, os.Stderr)

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	log.SetOutput(w)
	log.SetFlags(0)

	paths, err := filepath.Glob("../../*")
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(3)

	go func() {
		if err := main.Run(&main.Options{
			General: main.OptionsGeneral{
				Algorithm: "sha256",
			},
			Args: main.OptionsArgs{
				Paths: paths,
			},
		}); err != nil {
			t.Error(err)
		}
		os.Stdout.Close()
		wg.Done()
	}()

	var result string
	go func() {
		out := &bytes.Buffer{}
		if _, err := io.Copy(out, r); err != nil {
			t.Error(err)
		}
		result = strings.ToLower(out.String())
		wg.Done()
	}()

	var expected string
	go func() {
		out, err := exec.Command("shasum", append([]string{"-a", "256"}, paths...)...).CombinedOutput()
		if _, ok := err.(*exec.ExitError); err != nil && !ok {
			t.Error(err)
		}
		expected = strings.ToLower(strings.ReplaceAll(string(out), "shasum", "xsum"))
		wg.Done()
	}()

	wg.Wait()
	if result != expected {
		t.Fatalf("lower(xsum(./*)) =\n%sexpected:\n%s", result, expected)
	}
}
