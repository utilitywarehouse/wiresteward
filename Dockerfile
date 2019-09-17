FROM golang:alpine AS build
WORKDIR /go/src/github.com/utilitywarehouse/wiresteward
COPY . /go/src/github.com/utilitywarehouse/wiresteward
RUN \
  apk --no-cache add git gcc musl-dev \
  && go get -t ./... \
  && go test -v \
  && CGO_ENABLED=0 go build -ldflags='-s -w' -o /wiresteward .

FROM alpine:3.10
RUN apk add --no-cache ca-certificates
COPY --from=build /wiresteward /wiresteward
CMD [ "/wiresteward" ]
