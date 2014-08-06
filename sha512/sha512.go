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
	"sync"

	"github.com/developermail/crypt/base64"
	"github.com/developermail/crypt/salt"
)

// New() creates a sha512-crypt hash of key, using salt s
func New(key, s []byte) (result []byte, err error) {
	var (
		wg          sync.WaitGroup
		rounds      int
		isRoundsDef bool
	)

	s, rounds, isRoundsDef, err = salt.Parse(s)
	if err != nil {
		return
	}

	// Step 1-3
	A := sha512.New()
	A.Write(key)
	A.Write(s)

	// Step 4-8
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

	// Step 9-10
	A.Write(sequence(Bsum, len(key)))

	// Step 11-12
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

	// Step 13-15
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

	// Step 16
	P := sequence(DPsum, len(key))

	wg.Add(1)
	go func() {
		defer wg.Done()
		cleanSensitiveData(DPsum)
	}()

	// Step 17-19
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

	// Step 20
	S := sequence(DSsum, len(s))

	wg.Add(1)
	go func() {
		defer wg.Done()
		cleanSensitiveData(DSsum)
	}()

	// Step 21
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

	// Step 22
	// a)
	result = make([]byte, 0, 123)
	result = append(result, salt.MagicPrefix...)
	// b)
	if isRoundsDef {
		result = append(result, []byte("rounds="+strconv.Itoa(rounds)+"$")...)
	}
	// c)
	result = append(result, s...)
	// d)
	result = append(result, '$')
	// e)
	result = append(result, base64.Encode24Bit([]byte{
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

	wg.Wait()
	return
}

// NewWithPrefix() calls New() and prepends prefix to result
func NewWithPrefix(prefix string, key, s []byte) (result []byte, err error) {
	result, err = New(key, s)
	result = append([]byte(prefix), result...)
	return
}

// Verify() checks whether key is valid for hash hashedKey
func Verify(hash, key []byte) (ok bool, err error) {
	newHash, err := New(key, hash)
	if err != nil {
		return false, err
	}
	if bytes.Compare(newHash, hash) != 0 {
		// key doesn't match the given hash
		return false, nil
	}
	return true, nil
}

// VerifyWithPrefix() verifies a hash prefixed with a string
func VerifyWithPrefix(prefix string, hashWithPrefix, key []byte) (ok bool, err error) {
	hash := bytes.TrimLeft(hashWithPrefix, prefix)
	return Verify(hash, key)
}

func Cost(hash []byte) (int, error) {
	saltToks := bytes.Split(hash, []byte{'$'})
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
