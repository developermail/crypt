// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package apr1 implements the standard Unix MD5-crypt algorithm created
// by Poul-Henning Kamp for FreeBSD, and modified by the Apache project.
//
// The only change from MD5-crypt is the use of the magic constant "$apr1$"
// instead of "$1$". The algorithms are otherwise identical.
package apr1

import (
	"github.com/developermail/crypto"
	"github.com/developermail/crypto/common"
	"github.com/developermail/crypto/md5"
	"strings"
)

func init() {
	crypto.RegisterCrypt(crypto.APR1, New, MagicPrefix)
}

const (
	MagicPrefix   = "$apr1$"
	SaltLenMin    = 1
	SaltLenMax    = 8
	RoundsDefault = 1000
)

var md5Crypto = md5.New()

func init() {
	md5Crypto.SetSalt(common.Salt{
		MagicPrefix:   []byte(MagicPrefix),
		SaltLenMin:    SaltLenMin,
		SaltLenMax:    SaltLenMax,
		RoundsDefault: RoundsDefault,
	})
}

type crypter struct{ Salt common.Salt }

// New returns a new crypto.Crypter computing the variant "apr1" of MD5-crypt
func New() crypto.Crypter { return &crypter{common.Salt{}} }

func (c *crypter) Generate(key, salt []byte) (string, error) {
	return md5Crypto.Generate(key, salt)
}

func (c *crypter) GenerateWithPrefix(prefix string, key, salt []byte) (result string, err error) {
	result, err = c.Generate(key, salt)
	result = prefix + result
	return
}

func (c *crypter) Verify(hashedKey string, key []byte) error {
	return md5Crypto.Verify(hashedKey, key)
}

func (c *crypter) VerifyWithPrefix(prefix, hashedKey string, key []byte) error {
	hashedKey = strings.TrimLeft(hashedKey, prefix)
	return c.Verify(hashedKey, key)
}

func (c *crypter) Cost(hashedKey string) (int, error) { return RoundsDefault, nil }

func (c *crypter) SetSalt(salt common.Salt) {}
