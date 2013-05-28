all: passhash strip

cross:
	GOARM=5 GOARCH=arm GOOS=linux go build -o passhash_arm5 passhash.go
	GOARM=6 GOARCH=arm GOOS=linux go build -o passhash_arm6 passhash.go
	GOARM=7 GOARCH=arm GOOS=linux go build -o passhash_arm7 passhash.go
	GOARCH=386 GOOS=windows go build -o passhash_32.exe passhash.go
	GOARCH=amd64 GOOS=windows go build -o passhash_64.exe passhash.go

passhash: passhash.go
	go build passhash.go

format:
	gofmt -s -tabs=false -tabwidth=4 -w=true passhash.go

strip: passhash
	strip --strip-all passhash

clean:
	rm -f passhash passhash_arm7 passhash_arm5 passhash_32.exe passhash_64.exe
