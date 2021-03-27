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
	General struct {
		Algorithm string `short:"a" long:"algorithm" default:"sha256" description:"Use hashing algorithm"`
		Write     string `short:"w" long:"write" optional:"yes" optional-value:"default" description:"Write a separate, adjacent file for each checksum\nBy default, filename will be [orig-name].[alg]\nUse -w=ext or -wext to override extension (no space!)"`
		Check     bool   `short:"c" long:"check" description:"Validate checksums"`
		Status    bool   `short:"s" long:"status" description:"With --check, suppress all output"`
		Quiet     bool   `short:"q" long:"quiet" description:"With --check, suppress passing checksums"`
	} `group:"General Options"`

	Mask struct {
		Mask       string `short:"m" long:"mask" description:"Apply mask as [777]7[+ugx...]:\n+u\tInclude UID\n+g\tInclude GID\n+x\tInclude extended attrs\n+s\tInclude special file modes\n+t\tInclude modified time\n+c\tInclude created time\n+i\tInclude top-level metadata\n+n\tExclude file names\n+e\tExclude data\n+l\tAlways follow symlinks"`
		Directory  bool   `short:"d" long:"dirs" description:"Directory mode (implies: -m 0000)"`
		Portable   bool   `short:"p" long:"portable" description:"Portable mode, exclude names (implies: -m 0000+p)"`
		Git        bool   `short:"g" long:"git" description:"Git mode (implies: -m 0100)"`
		Full       bool   `short:"f" long:"full" description:"Full mode (implies: -m 7777+ug)"`
		Extended   bool   `short:"x" long:"extended" description:"Extended mode (implies: -m 7777+ugxs)"`
		Everything bool   `short:"e" long:"everything" description:"Everything mode (implies: -m 7777+ugxsct)"`
		Inclusive  bool   `short:"i" long:"inclusive" description:"Include top-level metadata (enables mask, adds +i)"`
		Follow     bool   `short:"l" long:"follow" description:"Follow symlinks (enables mask, adds +l)"`
		Opaque     bool   `short:"o" long:"opaque" description:"Encode mask to opaque, fixed-length hex (enables mask)"`
	} `group:"Mask Options"`

	Args struct {
		Paths []string `positional-arg-name:"paths"`
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
		opts.General.Check,
		opts.Mask.Mask != "",
		opts.Mask.Directory,
		opts.Mask.Portable,
		opts.Mask.Git,
		opts.Mask.Full,
		opts.Mask.Extended,
		opts.Mask.Everything) {
		log.Fatal("Only one of -c, -m, -p, -g, -f, -x, or -e permitted.")
	}
	if opts.General.Check && opts.Mask.Inclusive {
		log.Fatal("Only one of -c, -i permitted.")
	}
	if opts.General.Check && opts.Mask.Follow {
		log.Fatal("Only one of -c, -l permitted.")
	}
	if opts.General.Check && opts.Mask.Opaque {
		log.Fatal("Only one of -c, -o permitted.")
	}
	if opts.General.Check && opts.General.Write != "" {
		log.Fatal("Only one of -c, -w permitted.")
	}

	level := outputNormal
	if opts.General.Status {
		level = outputStatus
	} else if opts.General.Quiet {
		level = outputQuiet
	}
	alg, err := parseHash(opts.General.Algorithm)
	if err != nil {
		log.Fatalf("Invalid algorithm: %s", err)
	}
	if opts.General.Check {
		check(opts.Args.Paths, alg, level)
	} else {
		basic := false
		var mask sum.Mask
		switch {
		case opts.Mask.Mask != "":
			mask, err = sum.NewMaskString(opts.Mask.Mask)
			if err != nil {
				log.Fatalf("Invalid mask: %s", err)
			}
		case opts.Mask.Portable:
			mask = sum.NewMask(0000, sum.AttrNoName)
		case opts.Mask.Git:
			mask = sum.NewMask(0100, sum.AttrEmpty)
		case opts.Mask.Full:
			mask = sum.NewMask(7777, sum.AttrUID|sum.AttrGID)
		case opts.Mask.Extended:
			mask = sum.NewMask(7777, sum.AttrUID|sum.AttrGID|sum.AttrX|sum.AttrSpecial)
		case opts.Mask.Everything:
			mask = sum.NewMask(7777, sum.AttrUID|sum.AttrGID|sum.AttrX|sum.AttrSpecial|sum.AttrCtime|sum.AttrMtime)
		case opts.Mask.Directory, opts.Mask.Inclusive, opts.Mask.Follow, opts.Mask.Opaque: // inclusive+follow+opaque must be last on this list
			mask = sum.NewMask(0000, sum.AttrEmpty)
		default:
			basic = true
		}
		if opts.Mask.Inclusive {
			mask.Attr |= sum.AttrInclusive
		}
		if opts.Mask.Follow {
			mask.Attr |= sum.AttrFollow
		}
		if opts.General.Write != "" {
			if opts.General.Write == "default" {
				opts.General.Write = opts.General.Algorithm
			}
			write(opts.Args.Paths, mask, alg, basic, opts.Mask.Opaque, opts.General.Write)
		} else {
			output(opts.Args.Paths, mask, alg, basic, opts.Mask.Opaque)
		}
	}
}

func output(paths []string, mask sum.Mask, hash sum.Hash, basic, opaque bool) {
	if err := sum.New(basic).EachList(toFiles(paths, mask, hash), func(n *sum.Node) error {
		if n.Err != nil {
			log.Printf("xsum: %s", n.Err)
			return nil
		}
		fmt.Println(checksum(n, basic, opaque))
		return nil
	}); err != nil {
		log.Fatalf("xsum: %s", err)
	}
}

func checksum(n *sum.Node, basic, opaque bool) string {
	switch {
	case basic:
		return n.SumHex() + "  " + filepath.ToSlash(n.Path)
	case opaque:
		return n.Hex() + "  " + filepath.ToSlash(n.Path)
	default:
		return n.String() + "  " + filepath.ToSlash(n.Path)
	}
}

func write(paths []string, mask sum.Mask, alg sum.Hash, basic, opaque bool, ext string) {
	if err := sum.New(basic).EachList(toFiles(paths, mask, alg), func(n *sum.Node) error {
		if n.Err != nil {
			log.Printf("xsum: %s", n.Err)
			return nil
		}
		if n.Stdin {
			log.Print("xsum: skipping standard input")
			return nil
		}
		if ext == "" {
			ext = alg.String()
		}
		abs, err := filepath.Abs(n.Path)
		if err != nil {
			log.Printf("xsum: %s", n.Err)
			return nil
		}
		f, err := os.OpenFile(abs+"."+ext, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0777)
		if err != nil {
			log.Printf("xsum: %s", err)
			return nil
		}
		if _, err := fmt.Fprintln(f, checksum(n, basic, opaque)); err != nil {
			f.Close()
			log.Printf("xsum: %s", err)
			return nil
		}
		if err := f.Close(); err != nil {
			log.Printf("xsum: %s", err)
			return nil
		}
		return nil
	}); err != nil {
		log.Fatalf("xsum: %s", err)
	}
}

func check(indexes []string, alg sum.Hash, level outputLevel) {
	files := make(chan sum.File, 1)
	sums := make(chan string, 1)
	go func() {
		defer close(files)
		if len(indexes) == 0 {
			readIndexStdin(alg, func(f sum.File, sum string) {
				files <- f
				sums <- sum
			})
			return
		}
		for _, path := range indexes {
			switch path {
			case "-":
				readIndexStdin(alg, func(f sum.File, sum string) {
					files <- f
					sums <- sum
				})
			default:
				readIndexPath(path, alg, func(f sum.File, sum string) {
					files <- f
					sums <- sum
				})
			}
		}
	}()
	failed := 0
	if err := sum.New(false).Each(files, func(n *sum.Node) error {
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

func readIndexPath(path string, alg sum.Hash, fn func(sum.File, string)) {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("xsum: %s", err)
		return
	}
	defer f.Close()
	readIndex(f, path, alg, fn)
}

func readIndexStdin(alg sum.Hash, fn func(sum.File, string)) {
	readIndex(os.Stdin, "standard input", alg, fn)
}

func readIndex(f *os.File, path string, alg sum.Hash, fn func(sum.File, string)) {
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

		if p := strings.SplitN(hash, ":", 3); len(p) > 1 {
			var err error
			alg, err = parseHash(p[0])
			if err != nil {
				log.Printf("xsum: %s: invalid algorithm: %s", path, err)
				continue
			}
			hash = p[1]
			if len(p) > 2 {
				if len(p[2]) > 4 && p[2][4] != '+' {
					mask, err = sum.NewMaskHex(p[2])
					if err != nil {
						log.Printf("xsum: %s: invalid hex mask: %s", path, err)
						continue
					}
				} else {
					mask, err = sum.NewMaskString(p[2])
					if err != nil {
						log.Printf("xsum: %s: invalid mask: %s", path, err)
						continue
					}
				}
			}
		}
		fn(sum.File{Hash: alg, Path: fpath, Mask: mask}, strings.ToLower(hash))
	}
}

func toFiles(paths []string, mask sum.Mask, alg sum.Hash) []sum.File {
	var out []sum.File
	if len(paths) == 0 {
		out = append(out, sum.File{
			Hash:  alg,
			Path:  "-",
			Mask:  mask,
			Stdin: true,
		})
	}
	for _, path := range paths {
		stdin := false
		if path == "-" {
			stdin = true
		}
		out = append(out, sum.File{
			Hash:  alg,
			Path:  path,
			Mask:  mask,
			Stdin: stdin,
		})
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
