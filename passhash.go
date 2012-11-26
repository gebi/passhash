package main

import (
    "flag"
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
    var err error
    var rounds, cost int
    var hashname, kdname string
    flag.IntVar(&rounds, "rounds", 50000, "number of rounds")
    flag.StringVar(&hashname, "hash", "sha256", "hash to use")
    flag.StringVar(&kdname, "kd", "scrypt", "key derivation function")
    flag.IntVar(&cost, "cost", 14, "1<<cost parameter to scrypt")
    flag.Parse()

    if kdname == "scrypt" {
        hashname = "sha256"
    }
    args := flag.Args()
    h := str2hash[hashname]
    hashlength := h().Size()
    salt := make([]byte, hashlength)
    pw := []byte(args[0])
    if len(args) == 2 {
        if kdname == "bcrypt" {
            panic("Salt not supported for bcrypt")
        }
        salt, err = base64.URLEncoding.DecodeString(args[1])
        if err != nil {
            panic(err)
        }
        if len(salt) != hashlength {
            panic(fmt.Sprintf("salt not required size: %d needing %d bytes", len(salt), hashlength))
        }
    } else {
        n, err := rand.Read(salt)
        if n != len(salt) || err != nil {
            panic(err)
        }
    }
    var dk []byte

    switch kdname {
    case "pbkdf2":
        dk = pbkdf2.Key(pw, salt, rounds, hashlength , h)
    case "scrypt":
        dk, err = scrypt.Key(pw, salt, 1<<uint(cost), 8, 1, 32)
        if err != nil {
            panic(err)
        }
    case "bcrypt":
        if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
            panic("bcrypt: unsupported cost value")
        }
        dk, err = bcrypt.GenerateFromPassword(pw, cost)
        if err != nil {
            panic(err)
        }
        // safeguard against bcrypt working with wrong cost value
        if real_cost, err := bcrypt.Cost(dk); err != nil {
            panic(err)
        } else if cost != real_cost {
            panic("bcrypt did not generate hash with user provided cost value")
        }
    }

    salt_b64 := base64.URLEncoding.EncodeToString(salt)
    pwhash_b64 := base64.URLEncoding.EncodeToString(dk)

    fmt.Printf("%s$%s\n", salt_b64, pwhash_b64)
    //fmt.Printf("%x\n", dk)
}
