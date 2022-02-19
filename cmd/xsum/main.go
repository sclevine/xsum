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

	"github.com/sclevine/xsum"
	"github.com/sclevine/xsum/cli"
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
		Mask       string `short:"m" long:"mask" description:"Apply attribute mask as [777]7[+ugx...]:\n+u\tInclude UID\n+g\tInclude GID\n+s\tInclude special file modes\n+t\tInclude modified time\n+c\tInclude created time\n+x\tInclude extended attrs\n+i\tInclude top-level metadata\n+n\tExclude file names\n+e\tExclude data\n+l\tAlways follow symlinks"`
		Directory  bool   `short:"d" long:"dirs" description:"Directory mode (implies: -m 0000)"`
		Portable   bool   `short:"p" long:"portable" description:"Portable mode, exclude names (implies: -m 0000+p)"`
		Git        bool   `short:"g" long:"git" description:"Git mode (implies: -m 0100)"`
		Full       bool   `short:"f" long:"full" description:"Full mode (implies: -m 7777+ug)"`
		Extended   bool   `short:"x" long:"extended" description:"Extended mode (implies: -m 7777+ugxs)"`
		Everything bool   `short:"e" long:"everything" description:"Everything mode (implies: -m 7777+ugxsct)"`
		Inclusive  bool   `short:"i" long:"inclusive" description:"Include top-level metadata (enables mask, adds +i)"`
		Follow     bool   `short:"l" long:"follow" description:"Follow symlinks (enables mask, adds +l)"`
		Opaque     bool   `short:"o" long:"opaque" description:"Encode attribute mask to opaque, fixed-length hex (enables mask)"`
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
	alg, err := cli.ParseHash(opts.General.Algorithm)
	if err != nil {
		log.Fatalf("Invalid algorithm: %s", err)
	}
	if opts.General.Check {
		validateChecksums(opts.Args.Paths, alg, level)
	} else {
		basic := false
		var mask xsum.Mask
		switch {
		case opts.Mask.Mask != "":
			mask, err = xsum.NewMaskString(opts.Mask.Mask)
			if err != nil {
				log.Fatalf("Invalid mask: %s", err)
			}
		case opts.Mask.Portable:
			mask = xsum.NewMask(00000, xsum.AttrNoName)
		case opts.Mask.Git:
			mask = xsum.NewMask(00100, xsum.AttrEmpty)
		case opts.Mask.Full:
			mask = xsum.NewMask(07777, xsum.AttrUID|xsum.AttrGID)
		case opts.Mask.Extended:
			mask = xsum.NewMask(07777, xsum.AttrUID|xsum.AttrGID|xsum.AttrX|xsum.AttrSpecial)
		case opts.Mask.Everything:
			mask = xsum.NewMask(07777, xsum.AttrUID|xsum.AttrGID|xsum.AttrX|xsum.AttrSpecial|xsum.AttrCtime|xsum.AttrMtime)
		case opts.Mask.Directory, opts.Mask.Inclusive, opts.Mask.Follow, opts.Mask.Opaque: // inclusive+follow+opaque must be last on this list
			mask = xsum.NewMask(00000, xsum.AttrEmpty)
		default:
			basic = true
		}
		if opts.Mask.Inclusive {
			mask.Attr |= xsum.AttrInclusive
		}
		if opts.Mask.Follow {
			mask.Attr |= xsum.AttrFollow
		}
		if opts.General.Write != "" {
			if opts.General.Write == "default" {
				opts.General.Write = opts.General.Algorithm
			}
			writeChecksums(opts.Args.Paths, mask, alg, basic, opts.Mask.Opaque, opts.General.Write)
		} else {
			outputChecksums(opts.Args.Paths, mask, alg, basic, opts.Mask.Opaque)
		}
	}
}

func outputChecksums(paths []string, mask xsum.Mask, hash xsum.Hash, basic, opaque bool) {
	if err := xsum.New(basic).EachList(convertToFiles(paths, mask, hash), func(n *xsum.Node) error {
		if n.Err != nil {
			log.Printf("xsum: %s", n.Err)
			return nil
		}
		fmt.Println(formatChecksum(n, basic, opaque))
		return nil
	}); err != nil {
		log.Fatalf("xsum: %s", err)
	}
}

func formatChecksum(n *xsum.Node, basic, opaque bool) string {
	switch {
	case basic:
		return n.SumString() + "  " + filepath.ToSlash(n.Path)
	case opaque:
		return n.Hex() + "  " + filepath.ToSlash(n.Path)
	default:
		return n.String() + "  " + filepath.ToSlash(n.Path)
	}
}

func writeChecksums(paths []string, mask xsum.Mask, alg xsum.Hash, basic, opaque bool, ext string) {
	if err := xsum.New(basic).EachList(convertToFiles(paths, mask, alg), func(n *xsum.Node) error {
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
		if _, err := fmt.Fprintln(f, formatChecksum(n, basic, opaque)); err != nil {
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

func validateChecksums(indexes []string, alg xsum.Hash, level outputLevel) {
	files := make(chan xsum.File, 1)
	sums := make(chan string, 1)
	go func() {
		defer close(files)
		if len(indexes) == 0 {
			readIndexStdin(alg, func(f xsum.File, sum string) {
				files <- f
				sums <- sum
			})
			return
		}
		for _, path := range indexes {
			switch path {
			case "-":
				readIndexStdin(alg, func(f xsum.File, sum string) {
					files <- f
					sums <- sum
				})
			default:
				readIndexPath(path, alg, func(f xsum.File, sum string) {
					files <- f
					sums <- sum
				})
			}
		}
	}()
	failed := 0
	if err := xsum.New(false).Each(files, func(n *xsum.Node) error {
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

func readIndexPath(path string, alg xsum.Hash, fn func(xsum.File, string)) {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("xsum: %s", err)
		return
	}
	defer f.Close()
	readIndex(f, path, alg, fn)
}

func readIndexStdin(alg xsum.Hash, fn func(xsum.File, string)) {
	readIndex(os.Stdin, "standard input", alg, fn)
}

func readIndex(f *os.File, path string, alg xsum.Hash, fn func(xsum.File, string)) {
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

		var mask xsum.Mask

		if p := strings.SplitN(hash, ":", 3); len(p) > 1 {
			var err error
			alg, err = cli.ParseHash(p[0])
			if err != nil {
				log.Printf("xsum: %s: invalid algorithm: %s", path, err)
				continue
			}
			hash = p[1]
			if len(p) > 2 {
				if len(p[2]) > 4 && p[2][4] != '+' {
					mask, err = xsum.NewMaskHex(p[2])
					if err != nil {
						log.Printf("xsum: %s: invalid hex mask: %s", path, err)
						continue
					}
				} else {
					mask, err = xsum.NewMaskString(p[2])
					if err != nil {
						log.Printf("xsum: %s: invalid mask: %s", path, err)
						continue
					}
				}
			}
		}
		fn(xsum.File{Hash: alg, Path: fpath, Mask: mask}, strings.ToLower(hash))
	}
}

func convertToFiles(paths []string, mask xsum.Mask, alg xsum.Hash) []xsum.File {
	var out []xsum.File
	if len(paths) == 0 {
		out = append(out, xsum.File{
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
		out = append(out, xsum.File{
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
