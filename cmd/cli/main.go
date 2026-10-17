// Copyright © 2026, Vitalii Tarasenko. All rights reserved.
// Use of this source code is governed by a BSD-style license (BSD 3-Clause)
// that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"

	"github.com/vitalii012/fishcode/internal/crypto"
	"github.com/vitalii012/fishcode/internal/fileutils"
	"github.com/vitalii012/fishcode/internal/utils"
)

type command struct {
	input, output, mode string
}

func main() {
	var err error
	var cmd command

	if cmd, err = parseCommand(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	if cmd.mode == "help" {
		fmt.Println("FishCode (fishcode) v0.2")
		fmt.Println("Copyright \u00a9 2026, Vitalii Tarasenko.")
		fmt.Printf("Licensed under the BSD 3-Clause License.\n\n")
		fmt.Printf("Usage: fishcode <command> [flags]\n\n")
		fmt.Println("\t<lock> - make ciphertext from [-in] file")
		fmt.Println("\t<unlock> - make plaintext from [-in] file")
		fmt.Printf("\t<help> - print this dialog\n\n")
		fmt.Println("Note: use fishcode <command> [-h] to see sub-command manuals.")
	}

	var inputFile *os.File

	if inputFile, err = os.Open(cmd.input); err != nil {
		panic(err)
	}

	defer inputFile.Close()

	pwd := readPassword(cmd.mode)

	defer pwd.Cleanup()

	var outputFile *os.File

	if outputFile, err = os.Create(cmd.output); err != nil {
		panic(err)
	}

	defer outputFile.Close()

	var key crypto.Key

	defer key.Cleanup()

	if cmd.mode == "lock" {
		key.Generate(pwd)
	} else {
		if key.Salt, key.Tag, err = fileutils.LoadKeySupplements(inputFile); err != nil {
			panic(err)
		}

		key.Derive(pwd)
	}

	if cmd.mode == "lock" {
		if err = fileutils.StoreKeySupplements(outputFile, key.Salt, key.Tag); err != nil {
			panic(err)
		}

		if err = outputFile.Sync(); err != nil {
			panic(err)
		}
	}

	var cip crypto.Cipher

	if cip, err = crypto.InitCipher(pwd, &key); err != nil {
		panic(err)
	}

	if cmd.mode == "lock" {
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
			if cmd.mode == "lock" {
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
			if cmd.mode == "lock" {
				msg = cip.Lock(msg)
			} else {
				if msg, err = cip.Unlock(msg); err != nil {
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

func parseCommand(words []string) (command, error) {
	var cmd command

	if len(words) == 1 {
		return cmd, errors.New("command was not specified")
	}

	switch words[1] {
	case "lock":
		cmd.mode = words[1]

		fset := flag.NewFlagSet("lock", flag.ExitOnError)
		fset.StringVar(&cmd.input, "in", "", "file with plaintext")
		fset.StringVar(&cmd.output, "out", "ciphertext.bin", "file to store ciphertext")

		fset.Parse(words[2:])
	case "unlock":
		cmd.mode = words[1]

		fset := flag.NewFlagSet("unlock", flag.ExitOnError)
		fset.StringVar(&cmd.input, "in", "", "file with ciphertext")
		fset.StringVar(&cmd.output, "out", "plaintext.bin", "file to store plaintext")

		fset.Parse(words[2:])
	case "help":
		if len(words) != 2 {
			return cmd, errors.New("invalid usage")
		}

		cmd.mode = words[1]
	default:
		return cmd, errors.New("invalid command")
	}

	if cmd.input == "" {
		return cmd, errors.New("input file was not specified")
	}

	return cmd, nil
}

func readPassword(mode string) crypto.Password {
	fmt.Print("Password: ")

	if pdata, err := term.ReadPassword(int(os.Stdin.Fd())); err == nil {
		defer func() {
			for idx, _ := range pdata {
				pdata[idx] = 0
			}
		}()

		fmt.Println("")

		if err := utils.VerifyRawPassword(pdata); err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err)
			os.Exit(2)
		}

		if mode == "lock" {
			fmt.Print("Retype password: ")

			if pdata2, err := term.ReadPassword(int(os.Stdin.Fd())); err == nil {
				if err := utils.VerifyRawPassword(pdata2); err != nil {
					fmt.Fprintf(os.Stderr, "%s\n", err)
					os.Exit(3)
				}

				if !bytes.Equal(pdata, pdata2) {
					fmt.Fprintf(os.Stderr, "\nError: passwords don't match!\n")
					os.Exit(4)
				}
			} else {
				panic(err)
			}

			fmt.Println("")
		}

		return crypto.NewPassword(pdata)
	} else {
		panic(err)
	}
}
