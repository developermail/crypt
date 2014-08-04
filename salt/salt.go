// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package salt

import (
	"bytes"
	"crypto/rand"
	"errors"
	"github.com/developermail/crypt/base64"
	"strconv"
)

var (
	MagicPrefix   = []byte("$6$")
	RoundsDefault = 5000
	RoundsPrefix  = []byte("rounds=")
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

func Parse(rawsalt []byte) (s []byte, rounds int, isRoundsDef bool, err error) {
	if !bytes.HasPrefix(rawsalt, MagicPrefix) {
		err = errors.New("Invalid magic prefix")
		return
	}

	saltToks := bytes.SplitN(rawsalt, []byte{'$'}, 4)
	if len(saltToks) < 3 {
		err = errors.New("Invalid salt format")
		return
	}

	if bytes.HasPrefix(saltToks[2], RoundsPrefix) {
		s = saltToks[3]
		isRoundsDef = true

		var pr int64
		pr, err = strconv.ParseInt(string(saltToks[2][7:]), 10, 32)
		if err != nil {
			err = errors.New("Invalid rounds")
			return
		}

		rounds = int(pr)
	} else {
		s = saltToks[2]
		rounds = RoundsDefault
	}

	if len(s) > 16 {
		s = s[0:16]
	}

	return
}
