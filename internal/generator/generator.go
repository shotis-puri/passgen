// Package generator creates random passwords using crypto/rand.
package generator

import (
	"crypto/rand"
	"errors"
	"math"
	"math/big"
)

const (
	lower   = "abcdefghijklmnopqrstuvwxyz"
	upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits  = "0123456789"
	symbols = "!@#$%^&*()-_=+[]{};:,.<>?/~"

	ambiguous = "O0oIl1|"

	MinLength = 4
	MaxLength = 128
)

// Options controls which characters may appear in a password.
type Options struct {
	Length           int  `json:"length"`
	Lower            bool `json:"lower"`
	Upper            bool `json:"upper"`
	Digits           bool `json:"digits"`
	Symbols          bool `json:"symbols"`
	ExcludeAmbiguous bool `json:"excludeAmbiguous"`
}

// Result is a generated password plus its estimated strength.
type Result struct {
	Password    string  `json:"password"`
	EntropyBits float64 `json:"entropyBits"`
}

// Generate returns a password that contains at least one character from every
// enabled character set. Every random choice comes from crypto/rand.
func Generate(o Options) (Result, error) {
	if o.Length < MinLength || o.Length > MaxLength {
		return Result{}, errors.New("length must be between 4 and 128")
	}

	var sets []string
	for _, s := range []struct {
		on    bool
		chars string
	}{{o.Lower, lower}, {o.Upper, upper}, {o.Digits, digits}, {o.Symbols, symbols}} {
		if !s.on {
			continue
		}
		chars := s.chars
		if o.ExcludeAmbiguous {
			chars = remove(chars, ambiguous)
		}
		sets = append(sets, chars)
	}
	if len(sets) == 0 {
		return Result{}, errors.New("select at least one character type")
	}
	if o.Length < len(sets) {
		return Result{}, errors.New("length is too short for the selected character types")
	}

	var pool string
	for _, s := range sets {
		pool += s
	}

	out := make([]byte, 0, o.Length)
	for _, s := range sets { // guarantee one from each set
		c, err := pick(s)
		if err != nil {
			return Result{}, err
		}
		out = append(out, c)
	}
	for len(out) < o.Length {
		c, err := pick(pool)
		if err != nil {
			return Result{}, err
		}
		out = append(out, c)
	}
	if err := shuffle(out); err != nil {
		return Result{}, err
	}

	return Result{
		Password:    string(out),
		EntropyBits: math.Round(float64(o.Length)*math.Log2(float64(len(pool)))*10) / 10,
	}, nil
}

// pick returns a uniformly random byte from s (rand.Int avoids modulo bias).
func pick(s string) (byte, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(len(s))))
	if err != nil {
		return 0, err
	}
	return s[n.Int64()], nil
}

// shuffle is a Fisher-Yates shuffle driven by crypto/rand.
func shuffle(b []byte) error {
	for i := len(b) - 1; i > 0; i-- {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			return err
		}
		j := n.Int64()
		b[i], b[j] = b[j], b[i]
	}
	return nil
}

func remove(s, drop string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if !contains(drop, s[i]) {
			out = append(out, s[i])
		}
	}
	return string(out)
}

func contains(s string, c byte) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return true
		}
	}
	return false
}
