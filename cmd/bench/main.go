package main

import (
	"fmt"
	"io"
	"log"
	"time"

	"github.com/d4c5d1e0/kekcrypt"
	"github.com/d4c5d1e0/kekcrypt/internal/crypto"
)

func main() {
	max := 1 << 30               // ~~ 1gb
	buf := make([]byte, 1024*32) // 32kb buffer same as io.Copy which we use in the code

	wr, err := crypto.NewEncryptStreamWriter(&crypto.DerivedKey{
		Mac:      crypto.RandomBytes(32),
		Chacha:   crypto.RandomBytes(32),
		Filename: crypto.RandomBytes(16),
	}, crypto.RandomBytes(kekcrypt.NonceSize), io.Discard)
	if err != nil {
		log.Fatalf("error creating stream writer: %v", err)
	}

	start := time.Now()
	written := 0
	for written < max {
		n, err := wr.Write(buf)
		if err != nil {
			panic(err)
		}
		written += n
	}
	elapsed := time.Since(start)

	throughput := (float64(max) / elapsed.Seconds()) / (1024 * 1024)
	fmt.Printf("Throughput: %.2f MB/sec\n", throughput)

}
