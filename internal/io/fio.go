package io

import (
	"io"
	"os"
)

type InputFile struct {
	path   string
	handle *os.File
}

type OutputFile struct {
	path   string
	handle *os.File
}

func OpenInputFile(path string) (in InputFile, err error) {
	in.path = path

	if in.handle, err = os.Open(path); err != nil {
		return InputFile{path: path, handle: nil}, err
	}

	return in, nil
}

func (in *InputFile) Close() {
	if err := in.handle.Close(); err != nil {
		panic(err)
	}
}

func (in *InputFile) GetSize() (size int64, err error) {
	if size, err = in.handle.Seek(0, io.SeekEnd); err != nil {
		return 0, err
	}

	if _, err = in.handle.Seek(0, io.SeekStart); err != nil {
		return size, err
	}

	return size, nil
}

func (in *InputFile) LoadSalt(salt []byte) (err error) {
	if _, err = in.handle.Read(salt); err != nil {
		return err
	}

	return nil
}

func (in *InputFile) Read(block []byte) (err error) {
	if _, err = in.handle.Read(block); err != nil {
		return err
	}

	return nil
}

func CreateOutputFile(path string) (out OutputFile, err error) {
	out.path = path

	if out.handle, err = os.Create(path); err != nil {
		return OutputFile{path: path, handle: nil}, err
	}

	return out, nil
}

func (out *OutputFile) Close() {
	if err := out.handle.Close(); err != nil {
		panic(err)
	}
}

func (out *OutputFile) StoreSalt(salt []byte) (err error) {
	if _, err = out.handle.Write(salt); err != nil {
		return err
	}

	return nil
}

func (out *OutputFile) Sync() (err error) {
	if err = out.handle.Sync(); err != nil {
		return err
	}

	return nil
}

func (out *OutputFile) Write(block []byte) (err error) {
	if _, err = out.handle.Write(block); err != nil {
		return err
	}

	return nil
}
