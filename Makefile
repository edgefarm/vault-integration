REPOSITORY ?= $(shell minikube ip):5000
TAG ?= $(shell git describe --always)

DOCS = docs/index.pdf \
	docs/configuration.pdf \
	docs/enrollment.pdf \
	docs/setup-pki.pdf \
	docs/vault-concepts.pdf

all : install

install : test
	go install -v ./cmd/certretrieval

build : 
	go build -v ./cmd/certretrieval

test : build
	go test ./pkg/certretrieval


docker : docker.image docker.push

docker.image : 
	docker build -t $(REPOSITORY)/certretrieval:$(TAG) .
	docker tag $(REPOSITORY)/certretrieval:$(TAG) $(REPOSITORY)/certretrieval:latest

docker.push : 
	docker push $(REPOSITORY)/certretrieval:$(TAG)
	docker push $(REPOSITORY)/certretrieval:latest

%.pdf : %.md
	mkdir -p tmp/docs
	docker run --rm --name pandoc -v $(PWD):/data pandoc/latex -o tmp/$@ $<

docs : $(DOCS)

