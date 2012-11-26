all: passhash strip

passhash: passhash.go
	go build passhash.go

strip: passhash
	strip --strip-all passhash
