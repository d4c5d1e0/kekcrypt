# kekcrypt
## Installation 
- Install [Go](https://go.dev/dl/)
- Run the following command: 
```
$ go install github.com/d4c5d1e0/kekcrypt/cmd/kekcrypt@latest
```
- Done !
## Basic usage

```
Usage: kekcrypt [--mode MODE] [--file FILE] [--out OUT]

Options:
  --mode MODE, -m MODE   Set the mode, 'enc' for encryption / 'dec' for decryption
  --file FILE, -f FILE   Target file to encrypt or decrypt
  --out OUT, -o OUT      Where to write the encrypted/decrypted file, for decryption it defaults to the name of the file when encrypted, for encryption it just append .kek
  --help, -h             display this help and exit
```
- Encrypt `db.7z`
```
$ kekcrypt -m enc -f db.7z
```
- Decrypt it to `db.7z.dec`
```
$ kekcrypt -m dec -f db.7z.kek -o db.7z.dec
```

## Specs

- Files are encrypted with XChaCha20 and authenticated with HMAC-SHA512
- File names are encrypted with AES-GCM 128
- The keys are derived from the main password and a random salt with `argon2id` `rounds=4 memory=256*1024 threads=4`
