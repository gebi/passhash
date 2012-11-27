package main

import (
    flags "github.com/jessevdk/go-flags"
    "os"
    "log"
    "fmt"
    "hash"
    "crypto/rand"

    // hash
    "code.google.com/p/go.crypto/md4"
    "crypto/md5"
    "crypto/sha1"
    "crypto/sha256"
    "crypto/sha512"

    // key derivation function
    "code.google.com/p/go.crypto/pbkdf2"
    "code.google.com/p/go.crypto/bcrypt"
    "code.google.com/p/go.crypto/scrypt"

    // output encoding
    "encoding/base64"
)

var (
    str2hash = map[string] (func() hash.Hash) {
        "md4": md4.New,
        "md5": md5.New,
        "sha1": sha1.New,
        "sha224": sha256.New224,
        "sha256": sha256.New,
        "sha384": sha512.New384,
        "sha512": sha512.New,
    }
)


func main() {
    var opts struct {
        Rounds int `short:"r" long:"rounds" default:"50000" description:"Number of rounds"`
        Hashname string `long:"hash" default:"sha256" description:"Hash to use"`
        Kdname string `long:"kd" description:"Key derivation function"`
        Cost int `short:"c" long:"cost" default:"14" description:"Cost parameter to key derivation functions"`
    }
    opts.Rounds = 50000
    opts.Hashname = "sha256"
    opts.Kdname = "scrypt"
    opts.Cost = 14
    args, err := flags.Parse(&opts)
    if err != nil {
        os.Exit(1)
    }
    if len(args) == 0 {
        log.Fatal("Error: ", "Parameter password missing")
    }

    if opts.Kdname == "scrypt" {
        opts.Hashname = "sha256"
    }
    //println(opts.Rounds); println(opts.Hashname); println(opts.Kdname); println(opts.Cost)
    h, hash_available := str2hash[opts.Hashname]
    if ! hash_available {
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
        dk = pbkdf2.Key(pw, salt, opts.Rounds, hashlength , h)
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
        if real_cost, err := bcrypt.Cost(dk); err != nil {
            panic(err)
        } else if opts.Cost != real_cost {
            log.Fatal("Error: ", "bcrypt did not generate hash with user provided cost value")
        }
    }

    salt_b64 := base64.URLEncoding.EncodeToString(salt)
    pwhash_b64 := base64.URLEncoding.EncodeToString(dk)

    fmt.Printf("%s$%s\n", salt_b64, pwhash_b64)
    //fmt.Printf("%x\n", dk)
}
