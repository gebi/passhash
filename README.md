passhash
========

Create Secure Password Hashes with different algorithms.

I/O format is base64 conforming to RFC 4648 (also known as url safe base64 encoding).
If no salt is provided a cryptographically strong pseudo-random generator is used to generate
the salt through crypto/rand.Read (which uses either /dev/urandom on Unix like systems or
CryptGenRandom API on Windows).

Supported Key Derivation Functions with Default Parameters:

    *scrypt* default (CPU/memory cost parameter 1<<14))
    bcrypt           (cost value = 14)
    pbkdf2           (sha256 with 50000 rounds)

Supported Algorithms (pbkdf2):

    sha1, sha256, sha224, sha384, sha512
    md4, md5

Synopsis
--------

    Usage:
      passhash [OPTIONS] <password> [salt]

    Help Options:
      -h, --help    Show this help message

    Application Options:
      -r, --rounds  Number of rounds (50000)
          --hash    Hash to use (sha256)
          --kd      Key derivation function (scrypt)
      -c, --cost    Cost parameter to key derivation functions (14)

Examples
--------

Create scrypt hash with random generated salt

    % passhash foo
    CD41CIOQwUI9edSLfTrzLZMbPzcsw0wKURumS-AotvE=$Yg52dwMlJh2yuKoYAaBKEskDNtv961hRxWeW6AMXrnQ=

Create default pbkdf2 hash

    % passhash --kd pbkdf2 foo
    4NWdtaXy9ck3vT-yQiOQ2nkRKJWbUQWZFq9CHBf44DA=$8s5ucFdFBMEubBwIzaYLssqqRUO4Tag2MRqg-q8V-HY=

Create pbkdf2 hash with user provided salt

    % passhash -r 10000 --hash sha1 --kd pbkdf2 foo SMI22KXjdX_s6vzNIUuZIBl7BaA=
    SMI22KXjdX_s6vzNIUuZIBl7BaA=$izW_dQvHLt8pCoud04kjlqc47gM=

