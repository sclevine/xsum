package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sclevine/xsum/cli"
)

func main() {
	alg := "sha256"
	if strings.HasPrefix(os.Args[0], "xsum-pcm-") {
		alg = strings.TrimPrefix(os.Args[0], "xsum-pcm-")
	}

	switch os.Getenv("XSUM_PLUGIN_TYPE") {
	case "metadata":
		hash, err := cli.ParseHash(alg)
		if err != nil {
			log.Fatalf("Error: %s", err)
		}
		r, err := input()
		if err != nil {
			log.Fatalf("Error: %s", err)
		}
		defer r.Close()
		out, err := hash.Data(r)
		if err != nil {
			r.Close()
			log.Fatalf("Error: %s", err)
		}
		fmt.Printf("%x", out)
	default: // "data"
		if len(os.Args) < 2 {
			log.Fatal("Error: xsum PCM plugin does not support audio input via stdin")
		} else if len(os.Args) > 2 {
			log.Fatalf("Error: extra arguments: %s", strings.Join(os.Args[2:], ", "))
		}
		out, err := pcmSHA(os.Args[1], alg)
		if err != nil {
			log.Fatalf("Error: %s", err)
		}
		fmt.Print(out)
	}
}

func input() (io.ReadCloser, error) {
	switch len(os.Args) {
	case 0, 1:
		return io.NopCloser(os.Stdin), nil
	case 2:
		f, err := os.Open(os.Args[1])
		if err != nil {
			return nil, err
		}
		return f, nil
	default:
		return nil, fmt.Errorf("extra arguments: %s", strings.Join(os.Args[2:], ", "))
	}
}

func pcmSHA(path, alg string) (string, error) {
	ext := strings.ToLower(filepath.Ext(path))
	cmd := exec.Command("ffprobe",
		"-v", "error",
		"-select_streams", "a:0",
		"-show_entries", "stream=bits_per_raw_sample",
		"-of", "default=noprint_wrappers=1:nokey=1",
		path,
	)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			log.Printf("%s\n", ee.Stderr)
		}
		return "", err
	}
	bits := strings.TrimSpace(string(out))

	if bits == "N/A" {
		cmd := exec.Command("ffprobe",
			"-v", "error",
			"-select_streams", "a:0",
			"-show_entries", "stream=sample_fmt",
			"-of", "default=noprint_wrappers=1:nokey=1",
			path,
		)
		out, err := cmd.Output()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				log.Printf("%s\n", ee.Stderr)
			}
			return "", err
		}
		switch strings.TrimSpace(string(out)) {
		case "s16", "s16p":
			bits = "16"
		default:
			switch ext {
			case ".m4a":
				log.Printf("Warning: assuming '%s' is lossy m4a", path)
				fallthrough
			case ".mp3", ".ogg", ".opus":
				return pcmSHAOpt(path, "16", alg)
			default:
				return "", fmt.Errorf("invalid bit depth for '%s'", path)
			}
		}
	}

	if ext == ".flac" {
		real, err := pcmSHAOpt(path, bits, "md5")
		if err != nil {
			return "", err
		}
		claim, err := flacMD5(path)
		if err != nil {
			return "", err
		}
		if claim == "00000000000000000000000000000000" {
			log.Printf("Warning: flac '%s' missing PCM md5 checksum", path)
		} else if real != claim {
			return "", fmt.Errorf("corrupted flac '%s' (%s != %s)", path, claim, real)
		}
	}

	return pcmSHAOpt(path, bits, alg)
}

func pcmSHAOpt(path, bits, hash string) (string, error) {
	hashL := strings.ToLower(hash)
	hashU := strings.ToUpper(hash)
	cmd := exec.Command("ffmpeg",
		"-i", path,
		"-vn",
		"-c", "pcm_s"+bits+"le",
		"-f", "hash",
		"-hash", hashL,
		"-loglevel", "error",
		"-nostats",
		"-",
	)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			log.Printf("%s\n", ee.Stderr)
		}
		return "", err
	}
	if string(out[:len(hashU)+1]) != hashU+"=" ||
		len(out) <= len(hashU)+2 ||
		out[len(out)-1] != '\n' {
		return "", fmt.Errorf("invalid checksum '%s'", strings.TrimSpace(string(out)))
	}
	return string(out[len(hashU)+1 : len(out)-1]), nil
}

func flacMD5(path string) (string, error) {
	cmd := exec.Command("metaflac", "--show-md5sum", path)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			log.Printf("%s\n", ee.Stderr)
		}
		return "", err
	}
	if len(out) != 33 {
		return "", fmt.Errorf("invalid checksum '%s'", strings.TrimSpace(string(out)))
	}
	return string(out[:32]), nil
}
