// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sha512

import (
	"bytes"
	"testing"
)

func TestNew(t *testing.T) {
	data := []struct {
		salt []byte
		key  []byte
		out  []byte
		cost int
	}{
		{
			[]byte("$6$saltstring"),
			[]byte("Hello world!"),
			[]byte("$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"),
			5000,
		},
		{
			[]byte("$6$rounds=10000$saltstringsaltstring"),
			[]byte("Hello world!"),
			[]byte("$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."),
			10000,
		},
		{
			[]byte("$6$rounds=5000$toolongsaltstring"),
			[]byte("This is just a test"),
			[]byte("$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0"),
			5000,
		},
		{
			[]byte("$6$rounds=1400$anotherlongsaltstring"),
			[]byte("a very much longer text to encrypt. Kinda long.\nWith a linebreak."),
			[]byte("$6$rounds=1400$anotherlongsalts$g.gUQRW7IS01Gjoxx45nbrcyyZCRRdMKVSVIaXSBnk6HigfcRLqrj6E3SM9lFBsGJp4klvm1ygxV998PGCDiV/"),
			1400,
		},
		{
			[]byte("$6$rounds=77777$short"),
			[]byte("we have a short salt string but not a short password"),
			[]byte("$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0"),
			77777,
		},
		{
			[]byte("$6$rounds=123456$asaltof16chars.."),
			[]byte("a short string"),
			[]byte("$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"),
			123456,
		},
	}

	for i, d := range data {
		hash, err := New(d.key, d.salt)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Compare(hash, d.out) != 0 {
			t.Errorf("Test %d failed\nExpected: %s, got: %s", i, d.out, hash)
		}

		cost, err := Cost(hash)
		if err != nil {
			t.Fatal(err)
		}
		if cost != d.cost {
			t.Errorf("Test %d failed\nExpected: %d, got: %d", i, d.cost, cost)
		}
	}
}

func TestVerify(t *testing.T) {
	salt := []byte("$6$saltstring")
	data := [][]byte{
		[]byte("password"),
		[]byte("12345"),
		[]byte("That's amazing! I've got the same combination on my luggage!"),
		[]byte("And change the combination on my luggage!"),
		[]byte("         random  spa  c    ing."),
		[]byte("94ajflkvjzpe8u3&*j1k513KLJ&*()"),
	}
	for i, d := range data {
		hash, err := New(d, salt)
		if err != nil {
			t.Fatal(err)
		}
		ok, err := Verify(hash, d)
		if err != nil {
			t.Errorf("Test %d failed: Error verifying %s", i, d)
		}
		if ok != true {
			t.Errorf("Test %d failed: '%s' is not the correct key", i, d)
		}
	}
}

func TestNewWithPrefix(t *testing.T) {
	prefix := "{SHA512-CRYPT}"
	salt := []byte("$6$saltstring")
	data := [][]byte{
		[]byte("password"),
		[]byte("12345"),
		[]byte("That's amazing! I've got the same combination on my luggage!"),
		[]byte("And change the combination on my luggage!"),
		[]byte("         random  spa  c    ing."),
		[]byte("94ajflkvjzpe8u3&*j1k513KLJ&*()"),
	}
	for i, d := range data {
		hash, err := NewWithPrefix(prefix, d, salt)
		if err != nil {
			t.Fatal(err)
		}
		ok, err := VerifyWithPrefix(prefix, hash, d)
		if err != nil {
			t.Errorf("Test %d failed: Error verifying %s", i, d)
		}
		if ok != true {
			t.Error("Test %d failed: '%s' is not the correct key", i, d)
		}
	}
}
