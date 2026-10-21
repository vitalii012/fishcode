package crypto

import "bytes"

type Password struct {
	data []byte
}

func NewPassword(newData []byte) Password {
	return Password{data: bytes.Clone(newData)}
}

func (pwd *Password) Cleanup() {
	for idx := range pwd.data {
		pwd.data[idx] = 0
	}
}
