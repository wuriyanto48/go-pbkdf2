.PHONY : test build clean format

build:
	go build github.com/wuriyanto48/go-pbkdf2/cmd/go-pbkdf2

test:
	go test ./...

format:
	find . -name "*.go" -not -path "./vendor/*" -not -path ".git/*" | xargs gofmt -s -d -w