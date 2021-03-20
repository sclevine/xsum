package main

import (
	"bufio"
	"encoding/hex"
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
	Mask      string `short:"m" long:"mask" description:"Apply mask as [777]7[+ugx...]:\n+u\tInclude UID\n+g\tInclude GID\n+x\tInclude extended attrs\n+s\tInclude special file modes\n+t\tInclude modified time\n+c\tInclude created time\n+i\tInclude top-level metadata\n+n\tExclude file names\n+e\tExclude data\n+l\tAlways follow symlinks"`
	Status    bool   `short:"s" long:"status" description:"With --check, suppress all output"`
	Quiet     bool   `short:"q" long:"quiet" description:"With --check, suppress passing checksums"`

	Portable   bool `short:"p" long:"portable" description:"Portable mode, exclude names (implies: -m 0000+p)"`
	Git        bool `short:"g" long:"git" description:"Git mode (implies: -m 0100)"`
	Full       bool `short:"f" long:"full" description:"Full mode (implies: -m 7777+ug)"`
	Extended   bool `short:"x" long:"extended" description:"Extended mode (implies: -m 7777+ugxs)"`
	Everything bool `short:"e" long:"everything" description:"Everything mode (implies: -m 7777+ugxsct)"`

	Inclusive bool `short:"i" long:"inclusive" description:"Include top-level metadata (adds: +i)"`
	Symlinks  bool `short:"l" long:"symlinks" description:"Follow symlinks (adds: +l)"`

	Args struct {
		Paths []string `required:"1"`
	} `positional-args:"yes"`
}

type outputLevel int

const (
	outputNormal outputLevel = iota
	outputStatus
	outputQuiet
)

func main() {
	log.SetFlags(0)

	var opts Options
	parser := flags.NewParser(&opts, flags.HelpFlag|flags.PassAfterNonOption|flags.PassDoubleDash)
	rest, err := parser.Parse()
	if err != nil {
		if err, ok := err.(*flags.Error); ok && err.Type == flags.ErrHelp {
			log.Fatal(err)
		}
		log.Fatalf("Invalid arguments: %s", err)
	}
	if len(rest) != 0 {
		log.Fatalf("Unparsable arguments: %s", strings.Join(rest, ", "))
	}
	if multipleTrue(
		opts.Check,
		opts.Mask != "",
		opts.Portable,
		opts.Git,
		opts.Full,
		opts.Extended,
		opts.Everything) {
		log.Fatal("Only one of -c, -m, -p, -g, -f, -x, or -e permitted.")
	}
	if opts.Check && opts.Inclusive {
		log.Fatal("Only one of -c, -i permitted.")
	}
	if opts.Check && opts.Symlinks {
		log.Fatal("Only one of -c, -l permitted.")
	}

	level := outputNormal
	if opts.Status {
		level = outputStatus
	} else if opts.Quiet {
		level = outputQuiet
	}
	hf := parseHash(opts.Algorithm)
	if hf == nil {
		log.Fatalf("Invalid algorithm `%s'", opts.Algorithm)
	}
	if opts.Check {
		check(opts.Args.Paths, hf, level)
	} else {
		mask, err := sum.NewMaskString(opts.Mask)
		if err != nil {
			log.Fatalf("Invalid mask: %s", err)
		}
		switch {
		case opts.Portable:
			mask = sum.NewMask(0000, sum.AttrNoData)
		case opts.Git:
			mask = sum.NewMask(0100, sum.AttrEmpty)
		case opts.Full:
			mask = sum.NewMask(7777, sum.AttrUID|sum.AttrGID)
		case opts.Extended:
			mask = sum.NewMask(7777, sum.AttrUID|sum.AttrGID|sum.AttrX|sum.AttrSpecial)
		case opts.Everything:
			mask = sum.NewMask(7777, sum.AttrUID|sum.AttrGID|sum.AttrX|sum.AttrSpecial|sum.AttrCtime|sum.AttrMtime)
		}
		if opts.Inclusive {
			mask.Attr |= sum.AttrInclude
		}
		if opts.Symlinks {
			mask.Attr |= sum.AttrFollow
		}
		output(opts.Args.Paths, mask, hf)
	}
}

func output(paths []string, mask sum.Mask, hf hashFunc) {
	if err := sum.New(hf).EachList(toFiles(paths, mask), func(n *sum.Node) error {
		if n.Err != nil {
			log.Printf("xsum: %s", n.Err)
			return nil
		}
		fmt.Println(n.String() + "  " + filepath.ToSlash(n.Path))
		return nil
	}); err != nil {
		log.Fatalf("xsum: %s", err)
	}
}

func check(indexes []string, hf hashFunc, level outputLevel) {
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
		if hex.EncodeToString(n.Sum) != <-sums {
			if level != outputStatus {
				fmt.Println(n.Path + ": FAILED")
			}
			failed++
		} else {
			if level != outputStatus && level != outputQuiet {
				fmt.Println(n.Path + ": OK")
			}
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
		if level == outputStatus {
			os.Exit(1)
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
		fpath := lines[1]

		var mask sum.Mask
		if p := strings.SplitN(hash, ":", 2); len(p) == 2 {
			hash = p[0]
			mask, err = sum.NewMaskString(p[1])
			if err != nil {
				log.Printf("xsum: %s: invalid mask: %s", path, err)
				continue
			}
		}

		fn(sum.File{Path: fpath, Mask: mask}, strings.ToLower(hash))
	}
}

func toFiles(paths []string, mask sum.Mask) []sum.File {
	var out []sum.File
	for _, path := range paths {
		out = append(out, sum.File{path, mask})
	}
	return out
}

func multipleTrue(b ...bool) bool {
	var r bool
	for _, v := range b {
		if r && v {
			return true
		}
		r = r || v
	}
	return false
}
