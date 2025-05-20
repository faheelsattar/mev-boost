package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRelayCheckDisabled(t *testing.T) {
	backend := newTestBackend(t, 1, time.Second)
	// since newTestBackend sets relayCheck to true for all requests,
	// we need to override it to check the status when it is false
	backend.boost.relayCheck = false

	header := make(http.Header)
	header.Set(HeaderAccept, MediaTypeJSON)
	path := "/eth/v1/builder/status"

	rr := backend.request(t, http.MethodGet, path, header, nil)
	require.Equal(t, http.StatusOK, rr.Code)
	require.NotEmpty(t, rr.Header().Get("X-MEVBoost-Version"))
	require.Equal(t, 0, backend.relays[0].GetRequestCount(path))
}

func TestStatusRequestTimeout(t *testing.T) {
	t.Run("relay timeout", func(t *testing.T) {
		backend := newTestBackend(t, 1, 100*time.Millisecond)
		backend.relays[0].ResponseDelay = 200 * time.Millisecond

		header := make(http.Header)
		header.Set(HeaderAccept, MediaTypeJSON)
		path := "/eth/v1/builder/status"

		rr := backend.request(t, http.MethodGet, path, header, nil)
		require.Equal(t, http.StatusServiceUnavailable, rr.Code)
	})

	t.Run("multiple relays with different timeouts", func(t *testing.T) {
		backend := newTestBackend(t, 3, 200*time.Millisecond)
		backend.relays[0].ResponseDelay = 100 * time.Millisecond // Fast
		backend.relays[1].ResponseDelay = 300 * time.Millisecond // Slow
		backend.relays[2].ResponseDelay = 150 * time.Millisecond // Medium

		header := make(http.Header)
		header.Set(HeaderAccept, MediaTypeJSON)
		path := "/eth/v1/builder/status"

		rr := backend.request(t, http.MethodGet, path, header, nil)
		require.Equal(t, http.StatusOK, rr.Code)
	})
}
