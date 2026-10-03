// Copyright (c) 2026, Vitalii Tarasenko. All rights reserved.
// Use of this source code is governed by a BSD-style license
// (BSD 3-Clause) that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/term"
	"io"
	"os"
)

type Command struct {
	Input, Output, Mode string
}

type Password struct {
	data []byte
}

type Key struct {
	data      []byte
	salt, tag [32]byte
}

const (
	success  = 0
	cnsError = 1
	icError  = 2
	insError = 3
	iuError  = 4
	pdmError = 5
	ipError  = 6
	kvError  = 7
)

func main() {
	var cmd Command

	if len(os.Args) < 2 {
		cmd = ParseCommand([]string{})
	} else {
		cmd = ParseCommand(os.Args[1:])
	}

	var inputFile *os.File

	var err error

	if inputFile, err = os.Open(cmd.Input); err != nil {
		panic(err)
	}

	defer inputFile.Close()

	pwd := ReadPassword(cmd.Mode)

	defer pwd.Cleanup()

	var outputFile *os.File

	if outputFile, err = os.Create(cmd.Output); err != nil {
		panic(err)
	}

	defer outputFile.Close()

	var key Key

	defer key.Cleanup()

	if cmd.Mode == "lock" {
		key = GenerateKey(&pwd)
	} else {
		key = LoadKey(inputFile, &pwd)
	}

	var block cipher.Block

	if block, err = aes.NewCipher(key.data); err != nil {
		panic(err)
	}

	var aesGCM cipher.AEAD

	if aesGCM, err = cipher.NewGCMWithRandomNonce(block); err != nil {
		panic(err)
	}

	if cmd.Mode == "lock" {
		key.StoreSupplements(outputFile)

		if err = outputFile.Sync(); err != nil {
			panic(err)
		}
	}

	if cmd.Mode == "lock" {
		fmt.Print("Encryption...")
	} else {
		fmt.Print("Decryption...")
	}

	inputChan := make(chan []byte, 10)

	go func() {
		defer close(inputChan)

		var msg []byte
		var num int
		var err error

		for {
			if cmd.Mode == "lock" {
				msg = make([]byte, 1*1024*1024)
			} else {
				msg = make([]byte, 1*1024*1024+28)
			}

			if num, err = inputFile.Read(msg); err != nil {
				break
			} else {
				inputChan <- msg[:num]
			}
		}

		if err != io.EOF {
			panic(err)
		}

		if num > 0 {
			inputChan <- msg[:num]
		}
	}()

	cipherChan := make(chan []byte, 10)

	go func() {
		defer close(cipherChan)

		var err error

		for msg := range inputChan {
			if cmd.Mode == "lock" {
				msg = aesGCM.Seal(nil, make([]byte, 0), msg, nil)
			} else {
				if msg, err = aesGCM.Open(nil, make([]byte, 0), msg, nil); err != nil {
					panic(err)
				}
			}

			cipherChan <- msg
		}
	}()

	for msg := range cipherChan {
		if _, err := outputFile.Write(msg); err != nil {
			panic(err)
		}
	}

	if err = outputFile.Sync(); err != nil {
		panic(err)
	}

	fmt.Println("done!")
}

func ParseCommand(words []string) Command {
	if len(words) == 0 {
		fmt.Fprintf(os.Stderr, "Error: command was not specified!\n")
		os.Exit(cnsError)
	}

	var cmd Command

	if words[0] == "lock" {
		cmd.Mode = words[0]

		fset := flag.NewFlagSet("lock", flag.ExitOnError)
		fset.StringVar(&cmd.Input, "in", "", "file with plaintext")
		fset.StringVar(&cmd.Output, "out", "ciphertext.bin", "file to store ciphertext")

		fset.Parse(words[1:])
	} else if words[0] == "unlock" {
		cmd.Mode = words[0]

		fset := flag.NewFlagSet("unlock", flag.ExitOnError)
		fset.StringVar(&cmd.Input, "in", "", "file with ciphertext")
		fset.StringVar(&cmd.Output, "out", "plaintext.bin", "file to store plaintext")

		fset.Parse(words[1:])
	} else if words[0] == "help" {
		if len(words) != 1 {
			fmt.Fprintf(os.Stderr, "Error: invalid usage!\n")
			os.Exit(iuError)
		}

		fmt.Println("FishCode (fishcode) v0.1")
		fmt.Println("Copyright (c) 2026, Vitalii Tarasenko.")
		fmt.Printf("Licensed under the BSD 3-Clause License.\n\n")
		fmt.Printf("Usage: fishcode <command> [flags]\n\n")
		fmt.Println("\t<lock> - make ciphertext from [-in] file")
		fmt.Println("\t<unlock> - make plaintext from [-in] file")
		fmt.Printf("\t<help> - print this dialog\n\n")
		fmt.Println("Note: use fishcode <command> [-h] to see sub-command manuals.")

		os.Exit(success)
	} else {
		fmt.Fprintf(os.Stderr, "Error: invalid command!\n")
		os.Exit(icError)
	}

	if cmd.Input == "" {
		fmt.Fprintf(os.Stderr, "Error: input file was not specified!\n")
		os.Exit(insError)
	}

	return cmd
}

func verifyRawPassword(pwd []byte) error {
	if len(pwd) < 8 {
		return errors.New("Error: too short password!")
	}

	for _, sym := range pwd {
		if sym < 33 || sym > 126 {
			return errors.New("Error: password contains invalid symbols!")
		}
	}

	return nil
}

func ReadPassword(mode string) Password {
	fmt.Print("Password: ")

	if pdata, err := term.ReadPassword(int(os.Stdin.Fd())); err == nil {
		fmt.Println("")

		if err := verifyRawPassword(pdata); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(ipError)
		}

		if mode == "lock" {
			fmt.Print("Retype password: ")

			if pdata2, err := term.ReadPassword(int(os.Stdin.Fd())); err == nil {
				if err := verifyRawPassword(pdata2); err != nil {
					fmt.Fprintf(os.Stderr, "%s\n", err)
					os.Exit(ipError)
				}

				if !bytes.Equal(pdata, pdata2) {
					fmt.Fprintf(os.Stderr, "\nError: passwords don't match!\n")
					os.Exit(pdmError)
				}
			} else {
				panic(err)
			}

			fmt.Println("")
		}

		return Password{data: pdata}
	} else {
		panic(err)
	}
}

func (pwd *Password) Cleanup() {
	for idx := range pwd.data {
		pwd.data[idx] = 0
	}
}

func GenerateKey(pwd *Password) Key {
	var key Key

	rand.Read(key.salt[:])

	if data, err := pbkdf2.Key(sha256.New, string(pwd.data), key.salt[:], 4096, 32); err == nil {
		key.data = data
	} else {
		panic(err)
	}

	key.tag = sha256.Sum256(key.data)

	return key
}

func LoadKey(file *os.File, pwd *Password) Key {
	var key Key

	if _, err := file.Read(key.salt[:]); err != nil {
		panic(err)
	}
	if _, err := file.Read(key.tag[:]); err != nil {
		panic(err)
	}

	if data, err := pbkdf2.Key(sha256.New, string(pwd.data), key.salt[:], 4096, 32); err == nil {
		key.data = data
	} else {
		panic(err)
	}

	tag := sha256.Sum256(key.data)

	if !bytes.Equal(key.tag[:], tag[:]) {
		fmt.Fprintf(os.Stderr, "Error: invalid password!\n")
		os.Exit(kvError)
	}

	return key
}

func (key *Key) StoreSupplements(file *os.File) {
	if _, err := file.Write(key.salt[:]); err != nil {
		panic(err)
	}
	if _, err := file.Write(key.tag[:]); err != nil {
		panic(err)
	}
}

func (key *Key) Cleanup() {
	for idx := range key.data {
		key.data[idx] = 0
	}
}
