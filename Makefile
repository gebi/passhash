all: passhash strip

passhash: passhash.go
	go build passhash.go

format:
	gofmt -s -tabs=false -tabwidth=4 -w=true passhash.go

strip: passhash
	strip --strip-all passhash
