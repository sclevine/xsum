FROM golang:bullseye AS builder
WORKDIR /workspace
COPY . .
ARG version="0.0.0"
RUN go build -ldflags "-X main.Version=$version" ./cmd/xsum
FROM gcr.io/distroless/base-debian11
COPY --from=builder /workspace/xsum /bin/xsum
ENTRYPOINT ["/bin/xsum"]
