package main_test

import (
	"os"
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
			os.Stdin.Close()
			wg.Done()
		}()
		wg.Wait()
	}
}
