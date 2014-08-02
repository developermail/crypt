package base64

import "testing"
import "bytes"

func TestEncode24Bit(t *testing.T) {
	data := []struct {
		plain   []byte
		encoded []byte
	}{
		{
			[]byte("teststring to encode with 24bit base64"),
			[]byte("oJqQoB5RmZaPb/0Rj/GNiBqPYJ46rZ4Rc/WAo6KOo/WMVBLNqE1"),
		},
	}

	for i, d := range data {
		encoded := Encode24Bit(d.plain)
		if bytes.Compare(d.encoded, encoded) != 0 {
			t.Errorf("Test %d failed: %s", "Encode24Bit", i, d)
		}
	}
}
