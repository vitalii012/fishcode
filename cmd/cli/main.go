// Copyright © 2026, Vitalii Tarasenko. All rights reserved.

package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"

	"golang.org/x/term"

	"github.com/vitalii012/fishcode/internal/crypto"
	"github.com/vitalii012/fishcode/internal/io"
	"github.com/vitalii012/fishcode/internal/utils"
)

type command struct {
	input, output, mode string
}

type message struct {
	block         []byte
	total, number uint
}

type status struct {
	job     string
	percent uint
}

const blockSize = uint(1024)  // 1 KiB
const overheadSize = uint(28) // 28 B

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

	var in io.InputFile

	if in, err = io.OpenInputFile(cmd.input); err != nil {
		panic(err)
	}

	defer in.Close()

	pwd := readPassword(cmd.mode)

	defer pwd.Cleanup()

	var out io.OutputFile

	if out, err = io.CreateOutputFile(cmd.output); err != nil {
		panic(err)
	}

	defer out.Close()

	var key crypto.Key

	defer key.Cleanup()

	if cmd.mode == "lock" {
		key.Generate(pwd)

		if err = out.StoreSalt(key.GetSalt()); err != nil {
			panic(err)
		}
	} else {
		var salt [32]byte

		in.LoadSalt(salt[:])

		key.Derive(pwd, salt)
	}

	var cip crypto.Cipher

	defer cip.Cleanup()

	if cip, err = crypto.InitCipher(pwd, &key); err != nil {
		panic(err)
	}

	inputChan := make(chan message, 10)

	go func() {
		defer close(inputChan)

		var msg message

		fileSize := in.GetSize()

		var bytesLeft uint

		if cmd.mode == "lock" {
			msg.total = uint(fileSize) / blockSize
			bytesLeft = uint(fileSize) % blockSize
		} else {
			msg.total = (uint(fileSize) - key.GetSize()) / (blockSize + overheadSize)
			bytesLeft = (uint(fileSize) - key.GetSize()) % (blockSize + overheadSize)
		}

		readProcedure := func(chunkSize uint) {
			msg.block = make([]byte, chunkSize)

			if err = in.Read(msg.block); err != nil {
				panic(err)
			}

			msg.number++

			inputChan <- msg
		}

		for msg.number < msg.total {
			if cmd.mode == "lock" {
				readProcedure(blockSize)
			} else {
				readProcedure(blockSize + overheadSize)
			}
		}

		if bytesLeft > 0 {
			msg.total++

			if cmd.mode == "lock" {
				readProcedure(bytesLeft)
			} else {
				readProcedure(bytesLeft + overheadSize)
			}
		}
	}()

	cipherChan := make(chan message, 10)

	go func() {
		defer close(cipherChan)

		for msg := range inputChan {
			if cmd.mode == "lock" {
				msg.block = cip.Lock(msg.block)
			} else {
				if msg.block, err = cip.Unlock(msg.block); err != nil {
					panic(err)
				}
			}

			cipherChan <- msg
		}
	}()

	var sts status

	if cmd.mode == "lock" {
		sts.job = "Locking"
	} else {
		sts.job = "Unlocking"
	}

	stsText := fmt.Sprintf(
		"\r%s: %s \u2192 %s: %d%%",
		sts.job,
		cmd.input,
		cmd.output,
		sts.percent,
	)

	fmt.Print(stsText)

	for msg := range cipherChan {
		if err := out.Write(msg.block); err != nil {
			panic(err)
		}

		percent := (msg.number * 100) / msg.total

		if percent > sts.percent {
			sts.percent = percent

			stsText = fmt.Sprintf(
				"\r%s: %s \u2192 %s: %d%%",
				sts.job,
				cmd.input,
				cmd.output,
				sts.percent,
			)

			fmt.Print(stsText)
		}
	}

	if err = out.Sync(); err != nil {
		panic(err)
	}

	fmt.Print("\r")

	for idx := 0; idx < len(stsText); idx++ {
		fmt.Print(" ")
	}

	fmt.Println("\rDone!")
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
			for idx := range pdata {
				pdata[idx] = 0
			}
		}()

		fmt.Print("\r")

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

			fmt.Print("\r")
		}

		return crypto.NewPassword(pdata)
	} else {
		panic(err)
	}
}
