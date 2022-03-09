#!/bin/bash

set -e

version=${1:-0.0.0}
out=build-v${version}
cd "$(dirname "${BASH_SOURCE[0]}")"
mkdir -p "$out"

GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.Version=$version" -o "$out/xsum-macos-amd64" ./cmd/xsum
GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.Version=$version" -o "$out/xsum-macos-arm64" ./cmd/xsum
GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=$version" -o "$out/xsum-linux-amd64" ./cmd/xsum
GOOS=linux GOARCH=arm64 go build -ldflags "-X main.Version=$version" -o "$out/xsum-linux-arm64" ./cmd/xsum
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.Version=$version" -o "$out/xsum.exe" ./cmd/xsum

GOOS=darwin GOARCH=amd64 go build -ldflags "-X main.Version=$version" -o "$out/xsum-pcm-macos-amd64" ./cmd/xsum-pcm
GOOS=darwin GOARCH=arm64 go build -ldflags "-X main.Version=$version" -o "$out/xsum-pcm-macos-arm64" ./cmd/xsum-pcm
GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=$version" -o "$out/xsum-pcm-linux-amd64" ./cmd/xsum-pcm
GOOS=linux GOARCH=arm64 go build -ldflags "-X main.Version=$version" -o "$out/xsum-pcm-linux-arm64" ./cmd/xsum-pcm
GOOS=windows GOARCH=amd64 go build -ldflags "-X main.Version=$version" -o "$out/xsum-pcm.exe" ./cmd/xsum-pcm

docker build . --build-arg "version=$version" -t "sclevine/xsum:$version"
docker tag "sclevine/xsum:$version" "sclevine/xsum:latest"
docker build . -f Dockerfile.full --build-arg "version=$version" -t "sclevine/xsum:full-$version"
docker tag "sclevine/xsum:full-$version" "sclevine/xsum:full"