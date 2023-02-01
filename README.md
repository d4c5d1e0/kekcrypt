# kekcrypt

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
