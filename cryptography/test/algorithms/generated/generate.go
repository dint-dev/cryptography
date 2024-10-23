// RUNNING THIS:
//
//	go run blake2_test_vectors_generator.go
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/blake2s"
)

func main() {
	const path = "generated_test.dart"
	absPath, _ := filepath.Abs(path)
	os.Remove(path)
	w, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := w.Close(); err != nil {
			panic(err)
		}
	}()
	fmt.Printf("Creating \"%v\".\n", absPath)
	w.WriteString("import 'dart:typed_data';\n")
	w.WriteString("\n")
	w.WriteString("import 'package:cryptography_plus/cryptography_plus.dart';\n")
	w.WriteString("import 'package:cryptography_plus/src/utils.dart';\n")
	w.WriteString("import 'package:test/test.dart';\n")
	w.WriteString("\n")
	w.WriteString("import '_generated.dart';\n")
	w.WriteString("\n")
	w.WriteString("void main() {\n")

	// SHA256
	{
		const algo = "Sha256()"
		function := func(key, data []byte) []byte {
			tmp := sha256.Sum256(data)
			return tmp[:]
		}
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    []byte{},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    []byte{0},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    []byte{1},
		})
		for n := 31; n <= 33; n++ {
			writeHashTest(w, HashTest{
				algo:     algo,
				function: function,
				input:    make([]byte, n),
			})
		}
	}

	// HMAC-SHA256
	{
		const algo = "Hmac.sha256()"
		function := func(key, data []byte) []byte {
			w := hmac.New(sha256.New, key)
			w.Write(data)
			return w.Sum(nil)
		}
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      []byte{1, 2, 3},
			input:    []byte{},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      []byte{1, 2, 3},
			input:    []byte{0},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      []byte{1, 1, 1},
			input:    []byte{1},
		})
		for n := 31; n <= 33; n++ {
			writeHashTest(w, HashTest{
				algo:     algo,
				function: function,
				key:      make([]byte, n),
				input:    make([]byte, n),
			})
		}
	}

	// SHA384
	{
		const algo = "Sha384()"
		function := func(key, data []byte) []byte {
			tmp := sha512.Sum384(data)
			return tmp[:]
		}
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    []byte{},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    []byte{0},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    []byte{1},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    make([]byte, 63),
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    make([]byte, 64),
		})
		for n := 47; n <= 49; n++ {
			writeHashTest(w, HashTest{
				algo:     algo,
				function: function,
				input:    make([]byte, n),
			})
		}
		for n := 63; n <= 65; n++ {
			writeHashTest(w, HashTest{
				algo:     algo,
				function: function,
				input:    make([]byte, n),
			})
		}
	}

	// HMAC-SHA384
	{
		const algo = "Hmac.sha384()"
		function := func(key, data []byte) []byte {
			w := hmac.New(sha512.New384, key)
			w.Write(data)
			return w.Sum(nil)
		}
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      []byte{1, 2, 3},
			input:    []byte{},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      []byte{1, 2, 3},
			input:    []byte{0},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      []byte{1, 1, 1},
			input:    []byte{0},
		})
		for n := 47; n <= 49; n++ {
			writeHashTest(w, HashTest{
				algo:     algo,
				function: function,
				key:      make([]byte, n),
				input:    make([]byte, n),
			})
		}
		for n := 63; n <= 65; n++ {
			writeHashTest(w, HashTest{
				algo:     algo,
				function: function,
				key:      make([]byte, n),
				input:    make([]byte, n),
			})
		}
	}

	// SHA512
	{
		const algo = "Sha512()"
		function := func(key, data []byte) []byte {
			tmp := sha512.Sum512(data)
			return tmp[:]
		}
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    []byte{},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    []byte{0},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    []byte{1},
		})
		for n := 63; n <= 65; n++ {
			writeHashTest(w, HashTest{
				algo:     algo,
				function: function,
				input:    make([]byte, n),
			})
		}
	}

	// HMAC-SHA512
	{
		const algo = "Hmac.sha512()"
		function := func(key, data []byte) []byte {
			w := hmac.New(sha512.New, key)
			w.Write(data)
			return w.Sum(nil)
		}
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      []byte{1, 2, 3},
			input:    []byte{},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      []byte{1, 2, 3},
			input:    []byte{0},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      []byte{1, 1, 1},
			input:    []byte{0},
		})
		for n := 63; n <= 65; n++ {
			writeHashTest(w, HashTest{
				algo:     algo,
				function: function,
				key:      make([]byte, n),
				input:    make([]byte, n),
			})
		}
	}

	// BLAKE2B
	{
		const algo = "Blake2b()"
		function := func(key, data []byte) []byte {
			w, _ := blake2b.New512(key)
			w.Write(data)
			return w.Sum(nil)
		}
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    []byte{},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    []byte{0},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    []byte{1},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    make([]byte, 127),
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    make([]byte, 128),
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    make([]byte, 129),
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    make([]byte, 1000),
			cycles:   true,
		})

		//
		// With key
		//
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      make([]byte, 32),
			input:    []byte{},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      make([]byte, 64),
			input:    []byte{0},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      make([]byte, 64),
			input:    []byte{1},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      []byte{1, 2, 3},
			input:    []byte{0},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      []byte{1, 2, 3},
			input:    []byte{1},
		})
	}

	// BLAKE2B-256
	{
		const algo = "Blake2b(hashLengthInBytes: 32)"
		function := func(key, data []byte) []byte {
			w, _ := blake2b.New256(key)
			w.Write(data)
			return w.Sum(nil)
		}
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    []byte{},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    []byte{0},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    []byte{1},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    make([]byte, 127),
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    make([]byte, 128),
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    make([]byte, 129),
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    make([]byte, 1000),
			cycles:   true,
		})

		//
		// BLAKE2B-256 with key
		//
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      []byte{1, 2, 3},
			input:    []byte{},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      []byte{1, 2, 3},
			input:    []byte{0},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      []byte{1, 2, 3},
			input:    []byte{1},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      make([]byte, 32),
			input:    []byte{0},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      make([]byte, 32),
			input:    []byte{1},
		})
	}

	// BLAKE2S
	{
		const algo = "Blake2s()"
		function := func(key, data []byte) []byte {
			w, _ := blake2s.New256(key)
			w.Write(data)
			return w.Sum(nil)
		}
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    []byte{},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    []byte{0},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    []byte{1},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    make([]byte, 63),
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    make([]byte, 64),
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    make([]byte, 65),
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			input:    make([]byte, 1000),
			cycles:   true,
		})

		//
		// BLAKE2S with key
		//
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      []byte{1, 2, 3},
			input:    []byte{},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      []byte{1, 2, 3},
			input:    []byte{0},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      []byte{1, 2, 3},
			input:    []byte{1},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      make([]byte, 32),
			input:    []byte{0},
		})
		writeHashTest(w, HashTest{
			algo:     algo,
			function: function,
			key:      make([]byte, 32),
			input:    []byte{1},
		})
	}

	w.WriteString("}")
}

type HashTest struct {
	algo     string
	cycles   bool
	key      []byte
	input    []byte
	function func(key, data []byte) []byte
}

func writeHashTest(w io.Writer, hashTest HashTest) (hash.Hash, error) {
	// Allocate data
	key := hashTest.key
	data := hashTest.input

	// For each round
	var hash []byte
	if hashTest.cycles {
	    tmp := make([]byte, len(data))
	    copy(tmp, data)
		for i := 0; i < len(tmp); i++ {
			// Compute hash
			hash = hashTest.function(key, tmp[:i])

			// XOR bytes with the hash.
			// Thus the hash will be part of the input for the next round.
			for i := range tmp {
				tmp[i] ^= hash[i%len(hash)]
			}
		}
	} else {
		// Compute hash
		hash = hashTest.function(key, data)
	}
	fmt.Fprintf(w, "  test('%v", hashTest.algo)
	if key := hashTest.key; len(key) > 0 {
		fmt.Fprintf(w, "; key = %v", describeBytes(key))
	}
	if hashTest.cycles {
		fmt.Fprintf(w, "; %v cycles", len(data))
	} else {
		fmt.Fprintf(w, "; data = %v", describeBytes(data))
	}
	fmt.Fprintf(w, "', () async {\n")
	if len(hashTest.key) == 0 {
		fmt.Fprintf(w, "    await testHash(\n")
	} else {
		fmt.Fprintf(w, "    await testMac(\n")
	}
	fmt.Fprintf(w, "      algorithm: %v,\n", hashTest.algo)
	if hashTest.cycles {
		fmt.Fprintf(w, "      cycles: true,\n")
	}
	if len(hashTest.key) > 0 {
		fmt.Fprintf(w, "      key: %v,\n", bytesToDart(hashTest.key))
	}
	fmt.Fprintf(w, "      input: %v,\n", bytesToDart(data))
	fmt.Fprintf(w, "      expected: %v,\n", bytesToDart(hash))
	fmt.Fprintf(w, "    );\n")
	fmt.Fprintf(w, "  });\n")
	return nil, nil
}

func describeBytes(data []byte) string {
	if len(data) <= 3 {
		result := "["
		for i, item := range data {
			if i > 0 {
				result += ", "
			}
			result += fmt.Sprint(item)
		}
		result += "]"
		return result
	}
	return fmt.Sprintf("%v bytes", len(data))
}

func bytesToDart(data []byte) string {
	if len(data) <= 3 {
		return fmt.Sprintf("hexToBytes('%v')", hex.EncodeToString(data))
	}
	isDataZeroes := true
	for _, b := range data {
		if b != 0 {
			isDataZeroes = false
			break
		}
	}
	if isDataZeroes {
		return fmt.Sprintf("Uint8List(%v)", len(data))
	}
	return fmt.Sprintf("hexToBytes(\n        '%v',\n      )", hex.EncodeToString(data))
}
