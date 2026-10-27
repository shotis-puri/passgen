package vault

import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
)

func TestPBKDF2Vectors(t *testing.T) {
	cases := map[int]string{
		1: "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b",
		2: "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43",
	}
	for iter, want := range cases {
		if got := hex.EncodeToString(pbkdf2("password", []byte("salt"), iter, 32)); got != want {
			t.Errorf("iter %d: got %s", iter, got)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.json")
	v := New(path)
	if err := v.Create("master"); err != nil {
		t.Fatal(err)
	}
	e, err := v.Add(Entry{Name: "github", Password: "s3cret"})
	if err != nil {
		t.Fatal(err)
	}

	v2 := New(path)
	if err := v2.Unlock("wrong"); !errors.Is(err, ErrBadPassword) {
		t.Fatalf("want ErrBadPassword, got %v", err)
	}
	if err := v2.Unlock("master"); err != nil {
		t.Fatal(err)
	}
	list, _ := v2.List()
	if len(list) != 1 || list[0].Password != "s3cret" {
		t.Fatalf("unexpected entries: %+v", list)
	}

	if _, err := v2.Update(e.ID, Entry{Name: "gh", Password: "new"}); err != nil {
		t.Fatal(err)
	}
	if err := v2.Delete(e.ID); err != nil {
		t.Fatal(err)
	}
	v2.Lock()
	if _, err := v2.List(); !errors.Is(err, ErrLocked) {
		t.Fatalf("want ErrLocked, got %v", err)
	}
}
