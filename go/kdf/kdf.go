package kdf

import (
	c "github.com/christoffercarlsson/autograph/constants"
	e "github.com/christoffercarlsson/autograph/external"
	t "github.com/christoffercarlsson/autograph/types"
)

func Kdf(okm *t.Okm, ikm *t.Ikm) bool {
	salt := []byte{}
	okmSlice := okm[:]
	ikmSlice := ikm[:]
	return e.Hkdf(&okmSlice, &ikmSlice, &salt, &c.INFO)
}
