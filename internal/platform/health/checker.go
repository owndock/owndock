package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
)

type Checker struct {
	ready  atomic.Bool
	mu     sync.RWMutex
	checks map[string]func(context.Context) error
}

type response struct {
	Status string `json:"status"`
}

func NewChecker() *Checker {
	return &Checker{checks: make(map[string]func(context.Context) error)}
}

func (c *Checker) SetReady(ready bool) {
	c.ready.Store(ready)
}

func (c *Checker) AddReadinessCheck(name string, check func(context.Context) error) {
	if name == "" || check == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks[name] = check
}

func (c *Checker) Live(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, response{Status: "method_not_allowed"})
		return
	}
	writeJSON(w, http.StatusOK, response{Status: "ok"})
}

func (c *Checker) Ready(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, response{Status: "method_not_allowed"})
		return
	}
	if !c.ready.Load() {
		writeJSON(w, http.StatusServiceUnavailable, response{Status: "not_ready"})
		return
	}
	for _, check := range c.readinessChecks() {
		if err := check(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, response{Status: "not_ready"})
			return
		}
	}
	writeJSON(w, http.StatusOK, response{Status: "ok"})
}

func (c *Checker) readinessChecks() []func(context.Context) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	names := make([]string, 0, len(c.checks))
	for name := range c.checks {
		names = append(names, name)
	}
	sort.Strings(names)
	checks := make([]func(context.Context) error, 0, len(names))
	for _, name := range names {
		checks = append(checks, c.checks[name])
	}
	return checks
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
