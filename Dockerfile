FROM golang:1.16 as builder

RUN CGO_ENABLED=0 go install -v -gcflags="all=-N -l" github.com/go-delve/delve/cmd/dlv@v1.8.0

COPY . /srv

WORKDIR /srv

RUN CGO_ENABLED=0 go build -a -v -o /certretrieval -gcflags="all=-N -l"  ./cmd/certretrieval


FROM gcr.io/distroless/static

COPY --from=builder /certretrieval /certretrieval
COPY --from=builder /go/bin/dlv /

ENTRYPOINT [ "/certretrieval" ]

