package health

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
)

type Checker struct {
	ready atomic.Bool
}

type response struct {
	Status string `json:"status"`
}

func NewChecker() *Checker {
	return &Checker{}
}

func (c *Checker) SetReady(ready bool) {
	c.ready.Store(ready)
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
	writeJSON(w, http.StatusOK, response{Status: "ok"})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
