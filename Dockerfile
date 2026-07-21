FROM golang:1.26-alpine AS build
WORKDIR /go/src/github.com/utilitywarehouse/wiresteward
COPY . /go/src/github.com/utilitywarehouse/wiresteward
ENV CGO_ENABLED=0
# GOTOOLCHAIN pins the exact toolchain declared by go.mod's `go` line, so the
# build isn't at the mercy of whatever patch version the base image ships.
RUN apk --no-cache add git upx \
      && go get -t ./... \
      && go test -v \
      && GOTOOLCHAIN=go$(awk '/^go /{print $2; exit}' go.mod) \
      && go build -ldflags='-s -w' -o /wiresteward . \
      && upx /wiresteward

FROM alpine:3.21
RUN apk add --no-cache ca-certificates iptables
COPY --from=build /wiresteward /wiresteward
ENTRYPOINT [ "/wiresteward" ]
