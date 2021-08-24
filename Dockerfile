FROM golang:1.17-alpine AS build
WORKDIR /go/src/github.com/utilitywarehouse/wiresteward
COPY . /go/src/github.com/utilitywarehouse/wiresteward
ENV CGO_ENABLED=0
RUN apk --no-cache add git upx \
  && go get -t ./... \
  && go test -v \
  && go build -ldflags='-s -w' -o /wiresteward . \
  && upx /wiresteward

FROM alpine:3.14
RUN apk add --no-cache ca-certificates iptables
COPY --from=build /wiresteward /wiresteward
ENTRYPOINT [ "/wiresteward" ]
