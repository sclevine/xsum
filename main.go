package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/jessevdk/go-flags"

	"github.com/sclevine/xsum/sum"
)

type Options struct {
	Algorithm string `short:"a" long:"algorithm" default:"sha256" description:"Use hashing algorithm"`
	Check     bool   `short:"c" long:"check" description:"Validate checksums"`
	Mask      string `short:"m" long:"mask" default:"0000" description:"Apply mask"`
	Args      struct {
		Paths []string `required:"1"`
	} `positional-args:"yes"`
}

func main() {
	log.SetFlags(0)

	var opts Options
	parser := flags.NewParser(&opts, flags.HelpFlag|flags.PassAfterNonOption|flags.PassDoubleDash)
	rest, err := parser.Parse()
	if err != nil {
		log.Fatalf("Invalid arguments: %s", err)
	}
	if len(rest) != 0 {
		log.Fatalf("Unparsable arguments: %s", strings.Join(rest, ", "))
	}
	if opts.Check && opts.Mask != "0000" {
		log.Fatal("Mask must be read from checksum file and cannot be specified manually.")
	}
	if opts.Check {
		check(opts.Args.Paths, opts.Algorithm)
	} else {
		output(toFiles(opts.Args.Paths, opts.Mask), opts.Algorithm)
	}
}

func output(files []sum.File, alg string) {
	hf := parseHash(alg)
	if hf == nil {
		log.Fatalf("Invalid algorithm `%s'", alg)
	}
	if err := sum.New(hf).EachList(files, func(n *sum.Node) error {
		if n.Err != nil {
			log.Printf("xsum: %s", n.Err)
		}
		if n.Mode&os.ModeDir != 0 {
			fmt.Printf("%x:%s  %s\n", n.Sum, n.Mask, filepath.ToSlash(n.Path))
		} else {
			fmt.Printf("%x  %s\n", n.Sum, filepath.ToSlash(n.Path))
		}
		return nil
	}); err != nil {
		log.Printf("xsum: %s", err)
	}
}

func check(indexes []string, alg string) {
	hf := parseHash(alg)
	if hf == nil {
		log.Fatalf("Invalid algorithm `%s'", alg)
	}
	files := make(chan sum.File, 1)
	sums := make(chan string, 1)

	go func() {
		defer close(files)
		for _, path := range indexes {
			readIndex(path, func(f sum.File, sum string) {
				files <- f
				sums <- sum
			})
		}
	}()
	failed := 0
	if err := sum.New(hf).Each(files, func(n *sum.Node) error {
		if n.Err != nil {
			log.Printf("xsum: %s", n.Err)
		}
		if string(n.Sum) != <-sums {
			fmt.Printf("%s: FAILED\n", n.Path)
			failed++
		} else {
			fmt.Printf("%s: OK\n", n.Path)
		}
		return nil
	}); err != nil {
		log.Fatalf("xsum: %s", err)
	}
	if failed > 0 {
		plural := ""
		if failed > 1 {
			plural = "s"
		}
		log.Fatalf("xsum: WARNING: %d computed checksum%s did NOT match", failed, plural)
	}
}

func readIndex(path string, fn func(sum.File, string)) {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("xsum: %s", err)
		return
	}
	defer f.Close()
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		entry := scan.Text()
		lines := strings.SplitN(entry, "  ", 2)
		if len(lines) != 2 {
			log.Printf("xsum: %s: invalid entry `%s'", path, entry)
			continue
		}
		hash := lines[0]
		filepath := lines[1]

		var mask sum.Mask
		if p := strings.SplitN(hash, ":", 2); len(p) == 2 {
			hash = p[0]
			mask = sum.NewMaskString(p[1])
		}

		fn(sum.File{filepath, mask}, strings.ToLower(hash))
	}
}

func toFiles(paths []string, mask string) []sum.File {
	var out []sum.File
	for _, path := range paths {
		out = append(out, sum.File{path, sum.NewMaskString(mask)})
	}
	return out
}
