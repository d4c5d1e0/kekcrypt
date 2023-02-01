package main

import (
	"fmt"
	"log"
	"os"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/alexflint/go-arg"
	"github.com/d4c5d1e0/kekcrypt"
	"github.com/d4c5d1e0/kekcrypt/internal/crypto"
)

var args struct {
	Mode string `arg:"-m,--mode" help:"Set the mode, 'enc' for encryption / 'dec' for decryption" placeholder:"MODE" required:"true"`
	File string `arg:"-f,--file" help:"Target file to encrypt or decrypt" placeholder:"FILE" required:"true"`
	Out  string `arg:"-o,--out" help:"Where to write the encrypted/decrypted file, for decryption it defaults to the name of the file when encrypted, for encryption it just append .kek"`
}

type Mode int

const (
	Encrypt = iota
	Decrypt
)

func main() {
	arg.MustParse(&args)
	var mode Mode
	switch args.Mode {
	case "enc":
		mode = Encrypt
	case "dec":
		mode = Decrypt
	default:
		fmt.Printf("%s is not a valid mode, please chose 'dec' or 'enc'", args.Mode)
		os.Exit(1)
	}

	var salt []byte

	switch mode {
	case Encrypt:
		fmt.Print("Enter your secret password:")
		password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Fatalf("error reading password: %v", err)
		}
		fmt.Println()
		salt = crypto.RandomBytes(kekcrypt.SaltSize)
		key := crypto.DeriveKey(password, salt)

		enc := kekcrypt.NewEncrypter(args.File, key, salt)
		if err := enc.Encrypt(args.Out); err != nil {
			log.Fatalf("error encrypting target file: %v", err)
		}

		fmt.Println("Successfully encrypted your file")
	case Decrypt:
		header, err := kekcrypt.ParseHeader(args.File)
		if err != nil {
			log.Fatalf("error parsing header: '%v', make sure the provided file is correct and was encrypted with kekcrypt", err)
		}

		fmt.Print("Enter your secret password:")
		password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Fatalf("error reading password: %v", err)
		}

		fmt.Println()

		key := crypto.DeriveKey(password, header.Salt)

		decrypter := kekcrypt.NewDecrypter(args.File, key, header)
		if err := decrypter.Decrypt(args.Out); err != nil {
			log.Fatalf("error decrypting target file: %v", err)
		}

		fmt.Println("Successfully decrypted your file")
	}
}
