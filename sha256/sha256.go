// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha256_crypt implements Ulrich Drepper's SHA256-crypt password
// hashing algorithm.
//
// The specification for this algorithm can be found here:
// http://www.akkadia.org/drepper/SHA-crypt.txt
package sha256

import (
	"bytes"
	"crypto/sha256"
	"strconv"
	"sync"

	"github.com/developermail/crypto"
	"github.com/developermail/crypto/common"
)

func init() {
	crypto.RegisterCrypt(crypto.SHA256, New, MagicPrefix)
}

const (
	MagicPrefix   = "$5$"
	SaltLenMin    = 1
	SaltLenMax    = 16
	RoundsMin     = 1000
	RoundsMax     = 999999999
	RoundsDefault = 5000
)

var _rounds = []byte("rounds=")

type crypter struct{ Salt common.Salt }

// New returns a new crypto.Crypter computing the SHA256-crypt password hashing.
func New() crypto.Crypter {
	return &crypter{
		common.Salt{
			MagicPrefix:   []byte(MagicPrefix),
			SaltLenMin:    SaltLenMin,
			SaltLenMax:    SaltLenMax,
			RoundsDefault: RoundsDefault,
			RoundsMin:     RoundsMin,
			RoundsMax:     RoundsMax,
		},
	}
}

func (c *crypter) Generate(key, salt []byte) (result string, err error) {
	var (
		wg sync.WaitGroup

		rounds      int
		isRoundsDef bool
	)

	if len(salt) == 0 {
		salt = c.Salt.GenerateWRounds(SaltLenMax, RoundsDefault)[3:SaltLenMax]
		rounds = RoundsDefault
	} else {
		salt, rounds, isRoundsDef, err = c.parseSalt(salt)
		if err != nil {
			return
		}
	}

	// step 1-3
	A := sha256.New()
	A.Write(key)
	A.Write(salt)

	// step 4-8
	B := sha256.New()
	B.Write(key)
	B.Write(salt)
	B.Write(key)
	Bsum := B.Sum(nil)

	wg.Add(1)
	go func() {
		defer wg.Done()
		B.Reset()
	}()

	// step 9-10
	A.Write(c.sequence(Bsum, len(key)))

	// step 11-12
	for i := len(key); i > 0; i >>= 1 {
		if (i & 1) != 0 {
			A.Write(Bsum)
		} else {
			A.Write(key)
		}
	}
	Asum := A.Sum(nil)

	wg.Add(1)
	go func() {
		defer wg.Done()
		A.Reset()
	}()

	// step 13-15
	DP := sha256.New()
	for i := 0; i < len(key); i++ {
		DP.Write(key)
	}
	DPsum := DP.Sum(nil)

	wg.Add(1)
	go func() {
		defer wg.Done()
		DP.Reset()
	}()

	// step 16
	P := c.sequence(DPsum, len(key))

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.cleanSensitiveData(DPsum)
	}()

	// step 17-19
	DS := sha256.New()
	for i := 0; i < 16+int(Asum[0]); i++ {
		DS.Write(salt)
	}
	DSsum := DS.Sum(nil)

	wg.Add(1)
	go func() {
		defer wg.Done()
		DS.Reset()
	}()

	// step 20
	S := c.sequence(DSsum, len(salt))

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.cleanSensitiveData(DSsum)
	}()

	// step 21
	Csum := Asum

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.cleanSensitiveData(Asum)
	}()

	C := sha256.New()
	for i := 0; i < rounds; i++ {
		if (i & 1) > 0 {
			C.Write(P)
		} else {
			C.Write(Csum)
		}

		if i%3 > 0 {
			C.Write(S)
		}

		if i%7 > 0 {
			C.Write(P)
		}

		if i&1 > 0 {
			C.Write(Csum)
		} else {
			C.Write(P)
		}

		Csum = C.Sum(nil)
		C.Reset()
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		c.cleanSensitiveData(P)
	}()
	go func() {
		defer wg.Done()
		c.cleanSensitiveData(S)
	}()

	// step 22
	// a)
	out := make([]byte, 0, 123)
	out = append(out, c.Salt.MagicPrefix...)
	// b)
	if isRoundsDef {
		out = append(out, []byte("rounds="+strconv.Itoa(rounds)+"$")...)
	}
	// c)
	out = append(out, salt...)
	// d)
	out = append(out, '$')
	// e)
	out = append(out, common.Base64_24Bit([]byte{
		Csum[20], Csum[10], Csum[0],
		Csum[11], Csum[1], Csum[21],
		Csum[2], Csum[22], Csum[12],
		Csum[23], Csum[13], Csum[3],
		Csum[14], Csum[4], Csum[24],
		Csum[5], Csum[25], Csum[15],
		Csum[26], Csum[16], Csum[6],
		Csum[17], Csum[7], Csum[27],
		Csum[8], Csum[28], Csum[18],
		Csum[29], Csum[19], Csum[9],
		Csum[30], Csum[31],
	})...)

	result = string(out)

	wg.Wait()
	return
}

func (c *crypter) Verify(hashedKey string, key []byte) error {
	newHash, err := c.Generate(key, []byte(hashedKey))
	if err != nil {
		return err
	}
	if newHash != hashedKey {
		return crypto.ErrKeyMismatch
	}
	return nil
}

func (c *crypter) Cost(hashedKey string) (int, error) {
	saltToks := bytes.Split([]byte(hashedKey), []byte{'$'})
	if len(saltToks) < 3 {
		return 0, common.ErrSaltFormat
	}

	if !bytes.HasPrefix(saltToks[2], _rounds) {
		return RoundsDefault, nil
	}
	roundToks := bytes.Split(saltToks[2], []byte{'='})
	cost, err := strconv.ParseInt(string(roundToks[1]), 10, 0)
	return int(cost), err
}

func (c *crypter) SetSalt(salt common.Salt) { c.Salt = salt }

func (c *crypter) parseSalt(rawsalt []byte) (salt []byte, rounds int, isRoundsDef bool, err error) {
	if !bytes.HasPrefix(rawsalt, c.Salt.MagicPrefix) {
		err = common.ErrSaltPrefix
		return
	}

	saltToks := bytes.SplitN(rawsalt, []byte{'$'}, 4)
	if len(saltToks) < 3 {
		err = common.ErrSaltFormat
		return
	}

	if bytes.HasPrefix(saltToks[2], _rounds) {
		salt = saltToks[3]
		isRoundsDef = true

		var pr int64
		pr, err = strconv.ParseInt(string(saltToks[2][7:]), 10, 32)
		if err != nil {
			err = common.ErrSaltRounds
			return
		}

		rounds = int(pr)
		if rounds < RoundsMin {
			rounds = RoundsMin
		} else if rounds > RoundsMax {
			rounds = RoundsMax
		}
	} else {
		salt = saltToks[2]
		rounds = RoundsDefault
	}

	if len(salt) > SaltLenMax {
		salt = salt[0:SaltLenMax]
	}

	return
}

func (c *crypter) sequence(input []byte, length int) (sequence []byte) {
	sequence = make([]byte, 0)
	for ; length > 32; length -= 32 {
		sequence = append(sequence, input...)
	}
	sequence = append(sequence, input[0:length]...)

	return
}

func (c *crypter) cleanSensitiveData(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i] = 0
	}
}
