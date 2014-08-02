// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package salt

import (
	"crypto/rand"
	"errors"
	"github.com/developermail/crypto/base64"
	"strconv"
)

var (
	ErrSaltPrefix = errors.New("invalid magic prefix")
	ErrSaltFormat = errors.New("invalid salt format")
	ErrSaltRounds = errors.New("invalid rounds")

	MagicPrefix   = []byte("$6$")
	RoundsDefault = 5000
)

// New() generates a random salt of the given length, with the given rounds
func New(length, rounds int) []byte {
	saltLen := (length * 6 / 8)
	if (length*6)%8 != 0 {
		saltLen += 1
	}
	salt := make([]byte, saltLen)
	rand.Read(salt)

	// Append rounds if something else than the default is used
	roundsText := ""
	if rounds != RoundsDefault {
		roundsText = "rounds=" + strconv.Itoa(rounds) + "$"
	}

	out := make([]byte, len(MagicPrefix)+len(roundsText)+length)
	copy(out, MagicPrefix)
	copy(out[len(MagicPrefix):], []byte(roundsText))
	copy(out[len(MagicPrefix)+len(roundsText):], base64.Encode24Bit(salt))
	return out
}
