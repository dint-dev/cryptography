package main

import (
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/blake2s"
)

func main() {
	{
		value := []byte{}
		for i := 0; i < 10000; i++ {
			sum := blake2s.Sum256(value)
			value = sum[:]
		}
		fmt.Printf("blake2s, 10 000 cycles: %v\n", hex.EncodeToString(value))
	}
	{
		data := make([]byte, 10000)
		for i := 0; i < len(data); i++ {
			data[i] = byte(i % 256)
		}
		value := []byte{}
		for i := 0; i < 10000; i++ {
			w, _ := blake2s.New256(nil)
			w.Write(value)
			w.Write(data[:i])
			value = w.Sum(nil)
		}
		fmt.Printf("blake2s, 10 000 cycles, different lengths: %v\n", hex.EncodeToString(value))
	}
}
