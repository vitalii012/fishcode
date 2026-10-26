// Copyright © 2026, Vitalii Tarasenko. All rights reserved.

package utils

import "errors"

func VerifyRawPassword(pwd []byte) error {
	if len(pwd) < 8 {
		return errors.New("too short password")
	}

	for _, sym := range pwd {
		if sym < 33 || sym > 126 {
			return errors.New("password contains invalid symbols")
		}
	}

	return nil
}
