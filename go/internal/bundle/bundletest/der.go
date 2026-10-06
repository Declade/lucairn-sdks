package bundletest

import (
	"bytes"
	"encoding/asn1"
	"math/big"
	"sort"
	"time"
)

// Minimal DER writer for the synthetic RFC 3161 tokens.

func tlv(tag byte, content []byte) []byte {
	n := len(content)
	var l []byte
	switch {
	case n < 0x80:
		l = []byte{byte(n)}
	case n < 0x100:
		l = []byte{0x81, byte(n)}
	case n < 0x10000:
		l = []byte{0x82, byte(n >> 8), byte(n)}
	default:
		l = []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
	out := append([]byte{tag}, l...)
	return append(out, content...)
}

func seq(parts ...[]byte) []byte { return tlv(0x30, bytes.Join(parts, nil)) }
func set(parts ...[]byte) []byte { return tlv(0x31, bytes.Join(parts, nil)) }
func octet(b []byte) []byte      { return tlv(0x04, b) }
func null() []byte               { return []byte{0x05, 0x00} }

// sortedSetBody is the DER body of a SET OF: elements sorted by encoding.
func sortedSetBody(parts ...[]byte) []byte {
	sorted := append([][]byte(nil), parts...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i], sorted[j]) < 0 })
	return bytes.Join(sorted, nil)
}

func asn1OID(arcs ...int) asn1.ObjectIdentifier { return asn1.ObjectIdentifier(arcs) }

func oid(o asn1.ObjectIdentifier) []byte {
	b, err := asn1.Marshal(o)
	if err != nil {
		panic(err)
	}
	return b
}

func integer(n int64) []byte { return integerBig(big.NewInt(n)) }

func integerBig(n *big.Int) []byte {
	b, err := asn1.Marshal(n)
	if err != nil {
		panic(err)
	}
	return b
}

func generalizedTime(t time.Time) []byte {
	return tlv(0x18, []byte(t.UTC().Format("20060102150405Z")))
}
