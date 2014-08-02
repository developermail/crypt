// (C) Copyright 2012, Jeramey Crawford <jeramey@antihe.ro>. All
// rights reserved. Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package salt

import "testing"

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
			t.Errorf("Expected len %d, got len %d", i, len(s))
		}
	}
}
