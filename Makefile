build:
	go build -o ./out/server main.go

run: build
	./out/server

hot:
	reflex -s -r '\.go$$' make run
