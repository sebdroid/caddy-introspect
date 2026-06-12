package introspect

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheGetSet(t *testing.T) {
	c := newVerdictCache(10)
	key := sha256.Sum256([]byte("tok"))

	_, ok := c.get(key)
	assert.False(t, ok, "empty cache should miss")

	c.set(key, verdict{active: true}, time.Minute)
	v, ok := c.get(key)
	require.True(t, ok)
	assert.True(t, v.active)

	// negative verdicts are cached too
	negKey := sha256.Sum256([]byte("revoked"))
	c.set(negKey, verdict{reason: "revoked"}, time.Minute)
	v, ok = c.get(negKey)
	require.True(t, ok)
	assert.False(t, v.active)
	assert.Equal(t, "revoked", v.reason)
}

func TestCacheExpiry(t *testing.T) {
	c := newVerdictCache(10)
	key := sha256.Sum256([]byte("tok"))
	c.set(key, verdict{active: true}, 10*time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	_, ok := c.get(key)
	assert.False(t, ok, "expired entry should miss")
}

func TestCacheZeroTTLNotStored(t *testing.T) {
	c := newVerdictCache(10)
	key := sha256.Sum256([]byte("tok"))
	c.set(key, verdict{active: true}, 0)
	_, ok := c.get(key)
	assert.False(t, ok, "zero TTL must not store")
}

func TestCacheBounded(t *testing.T) {
	const max = 100
	c := newVerdictCache(max)
	for i := range max * 3 {
		key := sha256.Sum256(fmt.Appendf(nil, "tok-%d", i))
		c.set(key, verdict{active: true}, time.Minute)
	}
	assert.LessOrEqual(t, c.len(), max)
}
