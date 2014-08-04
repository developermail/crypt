// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package sha512_crypt implements Ulrich Drepper's SHA512-crypt password
// hashing algorithm.
//
// The specification for this algorithm can be found here:
// http://www.akkadia.org/drepper/SHA-crypt.txt
package sha512

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"strconv"
	"strings"
	"sync"

	"github.com/developermail/crypt/base64"
	"github.com/developermail/crypt/salt"
)

// New() creates a sha512-crypt hash of key, using salt s
func New(key, s []byte) (result string, err error) {
	var (
		wg          sync.WaitGroup
		rounds      int
		isRoundsDef bool
	)

	s, rounds, isRoundsDef, err = salt.Parse(s)
	if err != nil {
		return
	}

	// step 1-3
	A := sha512.New()
	A.Write(key)
	A.Write(s)

	// step 4-8
	B := sha512.New()
	B.Write(key)
	B.Write(s)
	B.Write(key)
	Bsum := B.Sum(nil)

	wg.Add(1)
	go func() {
		defer wg.Done()
		B.Reset()
	}()

	// step 9-10
	A.Write(sequence(Bsum, len(key)))

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
	DP := sha512.New()
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
	P := sequence(DPsum, len(key))

	wg.Add(1)
	go func() {
		defer wg.Done()
		cleanSensitiveData(DPsum)
	}()

	// step 17-19
	DS := sha512.New()
	for i := 0; i < 16+int(Asum[0]); i++ {
		DS.Write(s)
	}
	DSsum := DS.Sum(nil)

	wg.Add(1)
	go func() {
		defer wg.Done()
		DS.Reset()
	}()

	// step 20
	S := sequence(DSsum, len(s))

	wg.Add(1)
	go func() {
		defer wg.Done()
		cleanSensitiveData(DSsum)
	}()

	// step 21
	Csum := Asum

	wg.Add(1)
	go func() {
		defer wg.Done()
		cleanSensitiveData(Asum)
	}()

	C := sha512.New()
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
		cleanSensitiveData(P)
	}()
	go func() {
		defer wg.Done()
		cleanSensitiveData(S)
	}()

	// step 22
	// a)
	out := make([]byte, 0, 123)
	out = append(out, salt.MagicPrefix...)
	// b)
	if isRoundsDef {
		out = append(out, []byte("rounds="+strconv.Itoa(rounds)+"$")...)
	}
	// c)
	out = append(out, s...)
	// d)
	out = append(out, '$')
	// e)
	out = append(out, base64.Encode24Bit([]byte{
		Csum[42], Csum[21], Csum[0],
		Csum[1], Csum[43], Csum[22],
		Csum[23], Csum[2], Csum[44],
		Csum[45], Csum[24], Csum[3],
		Csum[4], Csum[46], Csum[25],
		Csum[26], Csum[5], Csum[47],
		Csum[48], Csum[27], Csum[6],
		Csum[7], Csum[49], Csum[28],
		Csum[29], Csum[8], Csum[50],
		Csum[51], Csum[30], Csum[9],
		Csum[10], Csum[52], Csum[31],
		Csum[32], Csum[11], Csum[53],
		Csum[54], Csum[33], Csum[12],
		Csum[13], Csum[55], Csum[34],
		Csum[35], Csum[14], Csum[56],
		Csum[57], Csum[36], Csum[15],
		Csum[16], Csum[58], Csum[37],
		Csum[38], Csum[17], Csum[59],
		Csum[60], Csum[39], Csum[18],
		Csum[19], Csum[61], Csum[40],
		Csum[41], Csum[20], Csum[62],
		Csum[63],
	})...)

	result = string(out)

	wg.Wait()
	return
}

// NewWithPrefix() calls New() but prepends a string to the result
func NewWithPrefix(prefix string, key, s []byte) (result string, err error) {
	result, err = New(key, s)
	result = prefix + result
	return
}

func Verify(hashedKey string, key []byte) error {
	newHash, err := New(key, []byte(hashedKey))
	if err != nil {
		return err
	}
	if newHash != hashedKey {
		return errors.New("Hashed value is not the hash of the given password")
	}
	return nil
}

// VerifyWithPrefix() verifies a hash prefixed with a string
func VerifyWithPrefix(prefix, hashedKey string, key []byte) error {
	hashedKey = strings.TrimLeft(hashedKey, prefix)
	return Verify(hashedKey, key)
}

func Cost(hashedKey string) (int, error) {
	saltToks := bytes.Split([]byte(hashedKey), []byte{'$'})
	if len(saltToks) < 3 {
		return 0, errors.New("Invalid salt format")
	}

	if !bytes.HasPrefix(saltToks[2], salt.RoundsPrefix) {
		return salt.RoundsDefault, nil
	}
	roundToks := bytes.Split(saltToks[2], []byte{'='})
	cost, err := strconv.ParseInt(string(roundToks[1]), 10, 0)
	return int(cost), err
}

func sequence(input []byte, length int) (sequence []byte) {
	sequence = make([]byte, 0)
	for ; length > 64; length -= 64 {
		sequence = append(sequence, input...)
	}
	sequence = append(sequence, input[0:length]...)

	return
}

func cleanSensitiveData(b []byte) {
	for i := 0; i < len(b); i++ {
		b[i] = 0
	}
}
