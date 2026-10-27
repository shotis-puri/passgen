# passgen

A small password generator and manager written in Go with **no third-party dependencies**.
Passwords are generated with `crypto/rand`, saved in an encrypted local vault, and managed through a simple web UI with a GitHub-style dark theme.

## Quick start

Requires Go 1.21+.

```sh
make run
# open http://127.0.0.1:8080  (use make run, not go run, on macOS with Go 1.21)
```

Or build a binary:

```sh
make build
./passgen
```

> **macOS note:** with Go 1.21 on newer macOS, binaries from `go run`/`go build` abort with `missing LC_UUID load command`. `make run` / `make build` work around this (external linker + `codesign`). Upgrading Go also fixes it.

Flags:

| Flag      | Default                 | Description                         |
|-----------|-------------------------|-------------------------------------|
| `-addr`   | `127.0.0.1:8080`        | Address to listen on                |
| `-vault`  | `~/.passgen/vault.json` | Path of the encrypted vault file    |

Run the tests with `go test ./...`.

## How it works

### Using the UI

1. **First run:** choose a master password (min. 8 characters). This creates the vault. The master password cannot be recovered.
2. **Generator (left):** pick length (4–128) and character types, then press *Generate*. The strength bar shows entropy in bits. *Copy* puts it on the clipboard; *Save to vault…* stores it as an entry.
3. **Vault (right):** search, add, edit, copy and delete entries (name, username, password, URL, notes).
4. **Lock vault** wipes the key and decrypted entries from server memory. Unlock again with the master password.

### Password generation (`internal/generator`)

- Every random choice uses `crypto/rand`; `rand.Int` is used to avoid modulo bias.
- At least one character from each selected set is guaranteed, then the rest is filled from the combined pool and the result is shuffled with a Fisher–Yates shuffle also driven by `crypto/rand`.
- Optionally excludes look-alike characters (`O 0 o I l 1 |`).
- Entropy estimate = `length × log2(pool size)`.

### Vault storage (`internal/vault`)

- The key is derived from the master password with PBKDF2-HMAC-SHA256 (600,000 iterations, random 16-byte salt).
- The entries are encrypted as one blob with AES-256-GCM using a fresh random nonce on every save; a wrong password fails authentication.
- The file is written atomically with `0600` permissions. Nothing is stored in plaintext.

### HTTP API (`internal/server`)

The UI is embedded into the binary (`go:embed`) and talks to a JSON API:

| Method & path              | Purpose                              |
|----------------------------|--------------------------------------|
| `GET /api/status`          | `{initialized, unlocked}`            |
| `POST /api/setup`          | Create the vault `{master}`          |
| `POST /api/unlock`         | Unlock `{master}`                    |
| `POST /api/lock`           | Lock                                 |
| `POST /api/generate`       | Generate a password from options     |
| `GET/POST /api/entries`    | List / create entries                |
| `PUT/DELETE /api/entries/{id}` | Update / delete an entry         |

Requests with a mismatched `Origin` header are rejected, and responses carry a strict Content-Security-Policy and `no-store` caching.

## Project layout

```
main.go                      entry point and flags
internal/generator/          crypto/rand password generator (+ tests)
internal/vault/              encrypted storage (+ tests)
internal/server/             HTTP handlers
internal/server/web/         index.html, style.css, app.js (embedded)
```

## Security notes

- Designed for **local, single-user** use. It listens on localhost by default and has no login sessions: anyone who can reach the port while the vault is unlocked can read it. Don't expose it to a network without adding TLS and authentication.
- Lock the vault when you're done; back up `vault.json` and remember your master password.
