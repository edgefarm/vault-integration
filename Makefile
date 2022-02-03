all : install

install : test
	go install -v ./cmd/certretrieval

build : 
	go build -v ./cmd/certretrieval

test : build
	go test ./pkg/certretrieval

