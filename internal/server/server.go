// Package server exposes the generator and vault over a small JSON API and
// serves the embedded web UI.
package server

import (
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"strings"

	"passgen/internal/generator"
	"passgen/internal/vault"
)

//go:embed web
var webFS embed.FS

type Server struct {
	vault *vault.Vault
}

func New(v *vault.Vault) http.Handler {
	s := &Server{vault: v}
	mux := http.NewServeMux()

	static, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(static)))

	mux.HandleFunc("/api/status", s.status)
	mux.HandleFunc("/api/setup", s.setup)
	mux.HandleFunc("/api/unlock", s.unlock)
	mux.HandleFunc("/api/lock", s.lock)
	mux.HandleFunc("/api/generate", s.generate)
	mux.HandleFunc("/api/entries", s.entries)
	mux.HandleFunc("/api/entries/", s.entry)

	return secure(mux)
}

// secure adds security headers and rejects cross-site state-changing requests.
func secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")

		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if o := r.Header.Get("Origin"); o != "" {
				if u, err := url.Parse(o); err != nil || u.Host != r.Host {
					http.Error(w, "cross-origin request blocked", http.StatusForbidden)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{
		"initialized": s.vault.Exists(),
		"unlocked":    s.vault.Unlocked(),
	})
}

type masterReq struct {
	Master string `json:"master"`
}

func (s *Server) setup(w http.ResponseWriter, r *http.Request) {
	var req masterReq
	if !decode(w, r, http.MethodPost, &req) {
		return
	}
	if len(req.Master) < 8 {
		writeErr(w, http.StatusBadRequest, errors.New("master password must be at least 8 characters"))
		return
	}
	if err := s.vault.Create(req.Master); err != nil {
		writeVaultErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) unlock(w http.ResponseWriter, r *http.Request) {
	var req masterReq
	if !decode(w, r, http.MethodPost, &req) {
		return
	}
	if err := s.vault.Unlock(req.Master); err != nil {
		writeVaultErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) lock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	s.vault.Lock()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) generate(w http.ResponseWriter, r *http.Request) {
	var opts generator.Options
	if !decode(w, r, http.MethodPost, &opts) {
		return
	}
	res, err := generator.Generate(opts)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) entries(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		list, err := s.vault.List()
		if err != nil {
			writeVaultErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, list)
	case http.MethodPost:
		var e vault.Entry
		if !decode(w, r, http.MethodPost, &e) || !validEntry(w, e) {
			return
		}
		saved, err := s.vault.Add(e)
		if err != nil {
			writeVaultErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, saved)
	default:
		methodNotAllowed(w)
	}
}

func (s *Server) entry(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/entries/")
	switch r.Method {
	case http.MethodPut:
		var e vault.Entry
		if !decode(w, r, http.MethodPut, &e) || !validEntry(w, e) {
			return
		}
		saved, err := s.vault.Update(id, e)
		if err != nil {
			writeVaultErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, saved)
	case http.MethodDelete:
		if err := s.vault.Delete(id); err != nil {
			writeVaultErr(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		methodNotAllowed(w)
	}
}

func validEntry(w http.ResponseWriter, e vault.Entry) bool {
	if strings.TrimSpace(e.Name) == "" {
		writeErr(w, http.StatusBadRequest, errors.New("name is required"))
		return false
	}
	return true
}

// decode checks the method and parses a size-limited JSON body into dst.
func decode(w http.ResponseWriter, r *http.Request, method string, dst any) bool {
	if r.Method != method {
		methodNotAllowed(w)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, errors.New("invalid JSON body"))
		return false
	}
	return true
}

func writeVaultErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, vault.ErrLocked), errors.Is(err, vault.ErrBadPassword):
		writeErr(w, http.StatusUnauthorized, err)
	case errors.Is(err, vault.ErrNotFound):
		writeErr(w, http.StatusNotFound, err)
	case errors.Is(err, vault.ErrInitialized), errors.Is(err, vault.ErrNotInitalized):
		writeErr(w, http.StatusConflict, err)
	default:
		writeErr(w, http.StatusInternalServerError, errors.New("internal error"))
	}
}

func methodNotAllowed(w http.ResponseWriter) {
	writeErr(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}
