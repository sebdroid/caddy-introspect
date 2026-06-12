package introspect

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// makeJWT builds an unsigned JWS-shaped token; the plugin never verifies
// signatures, so a dummy signature part suffices.
func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".sig"
}

func testProvision(t *testing.T, ti *TokenIntrospect) {
	t.Helper()
	require.NoError(t, ti.provision(zap.NewNop()))
}
