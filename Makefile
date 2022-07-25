build:
	CGO_ENABLED=1 go build -o ./out/server main.go

run: build
	./out/server

hot:
	reflex -s -r '\.go$$' make run
