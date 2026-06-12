package introspect

import (
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// verdictCache holds probe verdicts keyed by SHA-256 of the raw token, so
// tokens themselves are never stored. Negative verdicts are cached too;
// infrastructure errors never are.
type verdictCache struct {
	lru *lru.Cache[[32]byte, cacheEntry]
}

type cacheEntry struct {
	verdict   verdict
	expiresAt time.Time
}

func newVerdictCache(maxEntries int) *verdictCache {
	c, _ := lru.New[[32]byte, cacheEntry](max(maxEntries, 1)) // errs only when size < 1
	return &verdictCache{lru: c}
}

func (c *verdictCache) get(key [32]byte) (verdict, bool) {
	e, ok := c.lru.Get(key)
	if !ok || time.Now().After(e.expiresAt) {
		return verdict{}, false
	}
	return e.verdict, true
}

// set stores a verdict under its own expiry, which may be shorter than the
// configured TTL (entries are capped at the token's exp).
func (c *verdictCache) set(key [32]byte, v verdict, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	c.lru.Add(key, cacheEntry{verdict: v, expiresAt: time.Now().Add(ttl)})
}

func (c *verdictCache) len() int { return c.lru.Len() }
