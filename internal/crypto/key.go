// Copyright © 2026, Vitalii Tarasenko. All rights reserved.

package crypto

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
)

type Key struct {
	data []byte
	salt [32]byte
}

func (key *Key) GetSalt() []byte {
	return bytes.Clone(key.salt[:])
}

func (key *Key) GetSize() uint {
	return uint(len(key.data))
}

func (key *Key) Generate(pwd Password) (err error) {
	rand.Read(key.salt[:])

	if key.data, err = pbkdf2.Key(sha256.New, string(pwd.data), key.salt[:], 4096, 32); err != nil {
		return err
	}

	return nil
}

func (key *Key) Derive(pwd Password, salt [32]byte) (err error) {
	key.salt = salt

	if key.data, err = pbkdf2.Key(sha256.New, string(pwd.data), salt[:], 4096, 32); err == nil {
		return err
	}

	return nil
}

func (key *Key) Cleanup() {
	for idx := range key.data {
		key.data[idx] = 0
	}
}
