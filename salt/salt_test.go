// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package salt

import (
	"bytes"
	"testing"
)

func TestNew(t *testing.T) {
	// Test default rounds
	s := New(20, 5000)
	if len(s) != len(MagicPrefix)+20 {
		t.Errorf("Expected len 1, got len %d", len(s))
	}

	// Test different rounds and hash sizes
	for i := 1; i <= 20; i++ {
		s = New(i, 7000+i)
		if len(s) != len(MagicPrefix)+len("rounds=XXXX$")+i {
			t.Errorf("Expected len %d, got %d", i, len(s))
		}
	}
}

func TestParse(t *testing.T) {
	data := []struct {
		rawsalt     []byte
		salt        []byte
		rounds      int
		isRoundsDef bool
	}{
		{
			[]byte("$6$saltstring"),
			[]byte("saltstring"),
			5000,
			false,
		},
		{
			[]byte("$6$rounds=10000$thisisasalt"),
			[]byte("thisisasalt"),
			10000,
			true,
		},
		{
			[]byte("$6$rounds=10000$atoolongsaltstring"),
			[]byte("atoolongsaltstri"),
			10000,
			true,
		},
	}
	for _, d := range data {
		salt, rounds, isRoundsDef, err := Parse(d.rawsalt)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Compare(salt, d.salt) != 0 {
			t.Errorf("Expected salt %s, got %s\n", d.salt, salt)
		}
		if rounds != d.rounds {
			t.Errorf("Expected rounds %d, got %d\n", d.rounds, rounds)
		}
		if isRoundsDef != d.isRoundsDef {
			t.Errorf("Expected isRoundsDef %v, got %v\n", d.isRoundsDef, isRoundsDef)
		}
	}
}
