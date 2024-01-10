/*passhash is a command line utility to generate secure password hashes with scrypt bcrypt pbkdf3 md5 sha1 sha256 sha512

I/O format is base64 conforming to RFC 4648 (also known as url safe base64 encoding).
If no salt is provided a cryptographically strong pseudo-random generator is used to generate
the salt through crypto/rand.Read (which uses either /dev/urandom on Unix like systems or
CryptGenRandom API on Windows).

Supported Key Derivation Functions with Default Parameters:

    *scrypt* default (CPU/memory cost parameter 1<<14))
    bcrypt           (cost value = 14)
    pbkdf2           (sha256 with 50000 rounds)
    argon2           (FIXME)

Supported Algorithms (pbkdf2):

    sha1, sha256, sha224, sha384, sha512
    sha3-224, sha3-256, sha3-384, sha3-512
    md4, md5
*/
package main

import (
	"crypto/rand"
	"fmt"
	"hash"
	"log"
	"os"

	flags "github.com/jessevdk/go-flags"

	// hash
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"

	"golang.org/x/crypto/md4"
	"golang.org/x/crypto/sha3"

	// key derivation function
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"

	// output encoding
	"encoding/base64"
)

var (
	str2hash = map[string](func() hash.Hash){
		"md4":      md4.New,
		"md5":      md5.New,
		"sha1":     sha1.New,
		"sha224":   sha256.New224,
		"sha256":   sha256.New,
		"sha384":   sha512.New384,
		"sha512":   sha512.New,
		"sha3-224": sha3.New224,
		"sha3-256": sha3.New256,
		"sha3-384": sha3.New384,
		"sha3-512": sha3.New512,
	}
)

func main() {
	var opts struct {
		Rounds   int    `short:"r" long:"rounds" default:"50000" description:"Number of rounds"`
		Hashname string `long:"hash" default:"sha256" description:"Hash to use"`
		Kdname   string `long:"kd" description:"Key derivation function"`
		Cost     int    `short:"c" long:"cost" default:"14" description:"Cost parameter to key derivation functions"`
		Hmacenc  string `long:"hmacenc" default:"" description:"Base64 encoded password for final hmac encryption step"`
		Sha3enc  string `long:"sha3enc" default:"" description:"Base64 encoded password for final sha3 encryption step"`
	}
	opts.Rounds = 50000
	opts.Hashname = "sha256"
	opts.Kdname = "scrypt"
	opts.Cost = 14
	parser := flags.NewParser(&opts, flags.Default)
	parser.Usage = "[OPTIONS] <password> [salt]"
	parser.Usage += "\n\nSupported:\n"
	parser.Usage += "   KDF:\tscrpyt bcrypt pbkdf2 argon2\n"
	parser.Usage += "  HASH:\t"
	for i := range str2hash {
		parser.Usage += i + " "
	}
	args, err := parser.Parse()
	if err != nil {
		os.Exit(1)
	}
	if len(args) == 0 {
		log.Fatal("Error: ", "Parameter password missing")
	}

	if opts.Kdname == "bcrypt" && opts.Hmacenc != "" {
		log.Fatal("Error: bcrypt hash output can not be encrypted")
	}
	if opts.Kdname == "scrypt" {
		opts.Hashname = "sha256"
	}
	if opts.Hmacenc != "" && opts.Sha3enc != "" {
		log.Fatal("Error: you can not encrypt in the last step with both hmac and sha3, choose one")
	}
	var hmacencBin []byte
	if opts.Hmacenc != "" {
		hmacencBin, err = base64.URLEncoding.DecodeString(opts.Hmacenc)
		if err != nil {
			log.Fatal("Unable to decode hmac encryption password: ", err)
		}
	}
	var sha3encBin []byte
	if opts.Sha3enc != "" {
		sha3encBin, err = base64.URLEncoding.DecodeString(opts.Sha3enc)
		if err != nil {
			log.Fatal("Unable to decode sha3 encryption password: ", err)
		}
	}
	//println(opts.Rounds); println(opts.Hashname); println(opts.Kdname); println(opts.Cost)
	h, hashAvailable := str2hash[opts.Hashname]
	if !hashAvailable {
		log.Fatal("Error: ", "Unknown hash given: ", opts.Hashname)
	}
	hashlength := h().Size()
	salt := make([]byte, hashlength)
	pw := []byte(args[0])
	if len(args) == 2 {
		if opts.Kdname == "bcrypt" {
			log.Fatal("Error: ", "Salt not supported for bcrypt")
		}
		salt, err = base64.URLEncoding.DecodeString(args[1])
		if err != nil {
			log.Fatal("Error: ", "Could not base64 decode salt: ", err)
		}
		if len(salt) != hashlength {
			log.Fatalf("Error: Salt not required size: %d needing %d bytes", len(salt), hashlength)
		}
	} else {
		n, err := rand.Read(salt)
		if n != len(salt) || err != nil {
			log.Fatal("Error: ", "Could not generate salt: ", err)
		}
	}
	var dk []byte

	switch opts.Kdname {
	case "pbkdf2":
		dk = pbkdf2.Key(pw, salt, opts.Rounds, hashlength, h)
	case "scrypt":
		dk, err = scrypt.Key(pw, salt, 1<<uint(opts.Cost), 8, 1, 32)
		if err != nil {
			log.Fatal("Error: ", "in scrypt: ", err)
		}
	case "bcrypt":
		if opts.Cost < bcrypt.MinCost || opts.Cost > bcrypt.MaxCost {
			log.Fatal("Error: ", "bcrypt: unsupported cost value")
		}
		dk, err = bcrypt.GenerateFromPassword(pw, opts.Cost)
		if err != nil {
			log.Fatal("Error: ", "in bcrypt: ", err)
		}
		// safeguard against bcrypt working with wrong cost value
		if realCost, err := bcrypt.Cost(dk); err != nil {
			panic(err)
		} else if opts.Cost != realCost {
			log.Fatal("Error: ", "bcrypt did not generate hash with user provided cost value")
		}
	case "argon2":
		// FIXME - add support for arguments and different argon functions
		dk = argon2.IDKey(pw, salt, 1, 64*1024, 4, 32)
	default:
		log.Fatal("Error: unknown key derivation")
	}

	if opts.Hmacenc != "" {
		hmacEnc := hmac.New(h, hmacencBin)
		if _, err = hmacEnc.Write(dk); err != nil {
			log.Fatal("Error: error encrypting hash with hmac: ", err)
		}
		dk = hmacEnc.Sum(nil)
	}

	if opts.Sha3enc != "" {
		// FIXME encrypt with sha3
	}

	saltB64 := base64.URLEncoding.EncodeToString(salt)
	pwhashB64 := base64.URLEncoding.EncodeToString(dk)

	fmt.Printf("%s$%s\n", saltB64, pwhashB64)
	//fmt.Printf("%x\n", dk)
}
