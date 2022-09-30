TAG ?= $(shell git describe --always)
GO_LDFLAGS = -tags 'netgo osusergo static_build'

DOCS = docs/index.pdf \
	docs/configuration.pdf \
	docs/enrollment.pdf \
	docs/setup-pki.pdf \
	docs/vault-concepts.pdf

all : install

install : test
	go install $(GO_LDFLAGS) -v ./cmd/certretrieval

build : 
	go build $(GO_LDFLAGS) -v ./cmd/certretrieval

test : build
	go test ./pkg/certretrieval


%.pdf : %.md
	mkdir -p tmp/docs
	docker run --rm --name pandoc -v $(PWD):/data pandoc/latex -o tmp/$@ $<

docs : $(DOCS)

