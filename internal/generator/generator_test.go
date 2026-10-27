package generator

import (
	"strings"
	"testing"
)

func TestGenerateContainsEachSet(t *testing.T) {
	o := Options{Length: 12, Lower: true, Upper: true, Digits: true, Symbols: true}
	for i := 0; i < 500; i++ {
		r, err := Generate(o)
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Password) != 12 {
			t.Fatalf("length = %d", len(r.Password))
		}
		for name, set := range map[string]string{"lower": lower, "upper": upper, "digits": digits, "symbols": symbols} {
			if !strings.ContainsAny(r.Password, set) {
				t.Fatalf("%q missing %s", r.Password, name)
			}
		}
	}
}

func TestExcludeAmbiguous(t *testing.T) {
	o := Options{Length: 64, Lower: true, Upper: true, Digits: true, ExcludeAmbiguous: true}
	for i := 0; i < 200; i++ {
		r, _ := Generate(o)
		if strings.ContainsAny(r.Password, ambiguous) {
			t.Fatalf("ambiguous char in %q", r.Password)
		}
	}
}

func TestInvalidOptions(t *testing.T) {
	if _, err := Generate(Options{Length: 16}); err == nil {
		t.Error("expected error with no character sets")
	}
	if _, err := Generate(Options{Length: 2, Lower: true}); err == nil {
		t.Error("expected error for short length")
	}
	if _, err := Generate(Options{Length: 500, Lower: true}); err == nil {
		t.Error("expected error for long length")
	}
}
