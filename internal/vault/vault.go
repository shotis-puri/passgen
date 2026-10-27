// Package vault stores password entries in a single file encrypted with
// AES-256-GCM. The key is derived from a master password with PBKDF2-SHA256.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const iterations = 600_000

var (
	ErrLocked        = errors.New("vault is locked")
	ErrNotFound      = errors.New("entry not found")
	ErrBadPassword   = errors.New("wrong master password")
	ErrInitialized   = errors.New("vault already exists")
	ErrNotInitalized = errors.New("vault has not been created yet")
)

// Entry is one saved credential.
type Entry struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Username  string    `json:"username"`
	Password  string    `json:"password"`
	URL       string    `json:"url"`
	Notes     string    `json:"notes"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// file is the on-disk (encrypted) representation.
type file struct {
	Salt       []byte `json:"salt"`
	Iterations int    `json:"iterations"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// Vault is safe for concurrent use.
type Vault struct {
	path string

	mu      sync.Mutex
	key     []byte // nil while locked
	salt    []byte
	iters   int
	entries []Entry
}

func New(path string) *Vault { return &Vault{path: path} }

func (v *Vault) Exists() bool {
	_, err := os.Stat(v.path)
	return err == nil
}

func (v *Vault) Unlocked() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.key != nil
}

// Create initialises a new empty vault protected by master and leaves it unlocked.
func (v *Vault) Create(master string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.Exists() {
		return ErrInitialized
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	v.salt, v.iters = salt, iterations
	v.key = pbkdf2(master, salt, iterations, 32)
	v.entries = []Entry{}
	if err := v.save(); err != nil {
		v.key = nil
		return err
	}
	return nil
}

// Unlock decrypts the vault with master.
func (v *Vault) Unlock(master string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	raw, err := os.ReadFile(v.path)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotInitalized
	} else if err != nil {
		return err
	}
	var f file
	if err := json.Unmarshal(raw, &f); err != nil {
		return err
	}
	key := pbkdf2(master, f.Salt, f.Iterations, 32)
	gcm, err := newGCM(key)
	if err != nil {
		return err
	}
	plain, err := gcm.Open(nil, f.Nonce, f.Ciphertext, nil)
	if err != nil {
		return ErrBadPassword
	}
	var entries []Entry
	if err := json.Unmarshal(plain, &entries); err != nil {
		return err
	}
	v.key, v.salt, v.iters, v.entries = key, f.Salt, f.Iterations, entries
	return nil
}

// Lock wipes the key and decrypted entries from memory.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	for i := range v.key {
		v.key[i] = 0
	}
	v.key, v.entries = nil, nil
}

func (v *Vault) List() ([]Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return nil, ErrLocked
	}
	out := append([]Entry{}, v.entries...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (v *Vault) Add(e Entry) (Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return Entry{}, ErrLocked
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return Entry{}, err
	}
	now := time.Now().UTC()
	e.ID, e.CreatedAt, e.UpdatedAt = hex.EncodeToString(id), now, now
	v.entries = append(v.entries, e)
	return e, v.save()
}

func (v *Vault) Update(id string, e Entry) (Entry, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return Entry{}, ErrLocked
	}
	for i := range v.entries {
		if v.entries[i].ID == id {
			e.ID, e.CreatedAt, e.UpdatedAt = id, v.entries[i].CreatedAt, time.Now().UTC()
			v.entries[i] = e
			return e, v.save()
		}
	}
	return Entry{}, ErrNotFound
}

func (v *Vault) Delete(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.key == nil {
		return ErrLocked
	}
	for i := range v.entries {
		if v.entries[i].ID == id {
			v.entries = append(v.entries[:i], v.entries[i+1:]...)
			return v.save()
		}
	}
	return ErrNotFound
}

// save encrypts the entries with a fresh nonce and atomically replaces the file.
// The caller must hold v.mu.
func (v *Vault) save() error {
	gcm, err := newGCM(v.key)
	if err != nil {
		return err
	}
	plain, err := json.Marshal(v.entries)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	raw, err := json.Marshal(file{
		Salt:       v.salt,
		Iterations: v.iters,
		Nonce:      nonce,
		Ciphertext: gcm.Seal(nil, nonce, plain, nil),
	})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(v.path), 0o700); err != nil {
		return err
	}
	tmp := v.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, v.path)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// pbkdf2 implements PBKDF2 (RFC 8018) with HMAC-SHA256.
func pbkdf2(password string, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, []byte(password))
	var out []byte
	for block := uint32(1); len(out) < keyLen; block++ {
		prf.Reset()
		prf.Write(salt)
		var idx [4]byte
		binary.BigEndian.PutUint32(idx[:], block)
		prf.Write(idx[:])
		u := prf.Sum(nil)
		t := append([]byte{}, u...)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			subtle.XORBytes(t, t, u)
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
