package kdf

import (
	c "github.com/danba340/autograph/constants"
	e "github.com/danba340/autograph/external"
	t "github.com/danba340/autograph/types"
)

func Kdf(okm *t.Okm, ikm *t.Ikm) bool {
	salt := []byte{}
	okmSlice := okm[:]
	ikmSlice := ikm[:]
	return e.Hkdf(&okmSlice, &ikmSlice, &salt, &c.INFO)
}
