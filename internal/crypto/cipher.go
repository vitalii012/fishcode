package crypto

import (
	"crypto/aes"
	"crypto/cipher"
)

type Cipher struct {
	block  cipher.Block
	aesGCM cipher.AEAD
	key    *Key
}

func InitCipher(pwd Password, key *Key) (cip Cipher, err error) {
	if cip.block, err = aes.NewCipher(key.data); err != nil {
		return cip, err
	}

	if cip.aesGCM, err = cipher.NewGCMWithRandomNonce(cip.block); err != nil {
		return cip, err
	}

	cip.key = key

	return cip, nil
}

func (cip *Cipher) Lock(input []byte) []byte {
	return cip.aesGCM.Seal(nil, make([]byte, 0), input, nil)
}

func (cip *Cipher) Unlock(input []byte) (output []byte, err error) {
	if output, err = cip.aesGCM.Open(nil, make([]byte, 0), input, nil); err != nil {
		return output, err
	}

	return output, nil
}

func (cip *Cipher) Cleanup() {
	cip.key = nil
}
