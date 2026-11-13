// Copyright © 2026, Vitalii Tarasenko. All rights reserved.

package crypto

type Password struct {
	data []byte
}

func NewPassword(data []byte) *Password {
	return &Password{data}
}

func (pwd *Password) Cleanup() {
	for idx := range pwd.data {
		pwd.data[idx] = 0
	}
}
