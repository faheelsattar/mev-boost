package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	builderApiGloas "github.com/attestantio/go-builder-client/api/gloas"
	"github.com/attestantio/go-eth2-client/spec/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/flashbots/mev-boost/server/params"
	gloasAPI "github.com/flashbots/mev-boost/server/types/gloas"
	"github.com/stretchr/testify/require"
)

const (
	testParentHash = "0xe28385e7bd68df656cd0042b74b69c3104b5356ed1f20eb69f1f925df47a3ab7"
	testParentRoot = "0x1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809"
)

type testProposer struct {
	sk     *bls.SecretKey
	pubkey string
}

func newTestProposer(t *testing.T) testProposer {
	t.Helper()
	sk, pk, err := bls.GenerateNewKeypair()
	require.NoError(t, err)
	return testProposer{sk: sk, pubkey: hexutil.Encode(bls.PublicKeyToBytes(pk))}
}

func (p testProposer) signAuth(t *testing.T, data []byte, slot uint64) *builderApiGloas.SignedBuilderRequestAuth {
	t.Helper()
	msg := &builderApiGloas.BuilderRequestAuth{Data: data, Slot: phase0.Slot(slot)}
	domain := ssz.ComputeDomain(gloasAPI.DomainTypeBuilderRequestAuth, phase0.Version{}, phase0.Root{})
	root, err := ssz.ComputeSigningRoot(msg, domain)
	require.NoError(t, err)
	var sig phase0.BLSSignature
	copy(sig[:], bls.SignatureToBytes(bls.Sign(p.sk, root[:])))
	return &builderApiGloas.SignedBuilderRequestAuth{Message: msg, Signature: sig}
}

func bidPath(slot uint64, pubkey string) string {
	return fmt.Sprintf("/eth/v1/builder/execution_payload_bid/%d/%s/%s/%s", slot, testParentHash, testParentRoot, pubkey)
}

func gloasHeader(contentType, accept string, timeoutMs int) http.Header {
	h := http.Header{}
	h.Set(HeaderEthConsensusVersion, EthConsensusVersionGloas)
	h.Set(HeaderContentType, contentType)
	if accept != "" {
		h.Set(HeaderAccept, accept)
	}
	h.Set(HeaderDateMilliseconds, strconv.FormatInt(time.Now().UnixMilli(), 10))
	h.Set(HeaderTimeoutMs, strconv.Itoa(timeoutMs))
	return h
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}

// setDistinctAuthData gives every relay of the backend its own auth data, since the mock relays
// all share the 127.0.0.1 default.
func setDistinctAuthData(be *testBackend) {
	for i := range be.boost.relayConfigs {
		be.boost.relayConfigs[i].RelayEntry.AuthData = fmt.Sprintf("relay-%d", i)
	}
}

func TestGetExecutionPayloadBid(t *testing.T) {
	proposer := newTestProposer(t)

	t.Run("forwards the request unchanged and passes the bid through (JSON)", func(t *testing.T) {
		backend := newTestBackend(t, 1, time.Second)
		relay := backend.relays[0]
		auth := proposer.signAuth(t, []byte(relay.RelayEntry.AuthData), 1)
		body := mustJSON(t, auth)

		var received []byte
		var receivedHeader http.Header
		relay.OverrideHandleGetExecutionPayloadBid(func(w http.ResponseWriter, req *http.Request) {
			received, _ = io.ReadAll(req.Body)
			receivedHeader = req.Header.Clone()
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Eth-Consensus-Version", "gloas")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(gloasAPI.ExecutionPayloadBidResponse{Version: "gloas", Data: relay.MakeExecutionPayloadBid(777, 0, 1, testParentHash, testParentRoot, testParentHash)})
		})

		rr := backend.requestBytes(t, http.MethodPost, bidPath(1, proposer.pubkey), gloasHeader(MediaTypeJSON, MediaTypeJSON, 500), body)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		require.Equal(t, body, received, "auth must be forwarded byte-for-byte")
		require.Equal(t, "gloas", receivedHeader.Get(HeaderEthConsensusVersion))
		require.Equal(t, "application/json", receivedHeader.Get(HeaderContentType))
		require.NotEmpty(t, receivedHeader.Get(HeaderDateMilliseconds))
		fwdTimeout, err := strconv.Atoi(receivedHeader.Get(HeaderTimeoutMs))
		require.NoError(t, err)
		require.LessOrEqual(t, fwdTimeout, 500)
		require.Greater(t, fwdTimeout, 300)

		require.Equal(t, "application/json", rr.Header().Get(HeaderContentType))
		require.Equal(t, "gloas", rr.Header().Get(HeaderEthConsensusVersion))
		var bid gloasAPI.ExecutionPayloadBidResponse
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &bid))
		require.Equal(t, "gloas", bid.Version)
		require.Equal(t, phase0.Gwei(777), bid.Data.Message.Value)
		require.Equal(t, phase0.Slot(1), bid.Data.Message.Slot)
	})

	t.Run("SSZ request and SSZ response", func(t *testing.T) {
		backend := newTestBackend(t, 1, time.Second)
		relay := backend.relays[0]
		auth := proposer.signAuth(t, []byte(relay.RelayEntry.AuthData), 1)
		body, err := auth.MarshalSSZ()
		require.NoError(t, err)

		rr := backend.requestBytes(t, http.MethodPost, bidPath(1, proposer.pubkey), gloasHeader(MediaTypeOctetStream, MediaTypeOctetStream, 500), body)
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		require.Equal(t, MediaTypeOctetStream, rr.Header().Get(HeaderContentType))
		require.Equal(t, "gloas", rr.Header().Get(HeaderEthConsensusVersion))
		var bid gloas.SignedExecutionPayloadBid
		require.NoError(t, bid.UnmarshalSSZ(rr.Body.Bytes()))
		require.Equal(t, phase0.Gwei(12345), bid.Message.Value)
		require.Equal(t, testParentHash, bid.Message.ParentBlockHash.String())
	})

	t.Run("routes by auth data to exactly one relay", func(t *testing.T) {
		backend := newTestBackend(t, 3, time.Second)
		setDistinctAuthData(backend)
		auth := proposer.signAuth(t, []byte("relay-1"), 1)

		rr := backend.requestBytes(t, http.MethodPost, bidPath(1, proposer.pubkey), gloasHeader(MediaTypeJSON, "", 500), mustJSON(t, auth))
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		require.Equal(t, 0, backend.relays[0].GetRequestCount(bidPath(1, proposer.pubkey)))
		require.Equal(t, 1, backend.relays[1].GetRequestCount(bidPath(1, proposer.pubkey)))
		require.Equal(t, 0, backend.relays[2].GetRequestCount(bidPath(1, proposer.pubkey)))
	})

	t.Run("relay 204 and 400 are passed through, 5xx becomes 502", func(t *testing.T) {
		backend := newTestBackend(t, 1, time.Second)
		relay := backend.relays[0]
		auth := proposer.signAuth(t, []byte(relay.RelayEntry.AuthData), 1)
		body := mustJSON(t, auth)

		relay.OverrideHandleGetExecutionPayloadBid(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
		rr := backend.requestBytes(t, http.MethodPost, bidPath(1, proposer.pubkey), gloasHeader(MediaTypeJSON, "", 500), body)
		require.Equal(t, http.StatusNoContent, rr.Code)

		relay.OverrideHandleGetExecutionPayloadBid(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, `{"code":400,"message":"relay says no"}`, http.StatusBadRequest)
		})
		rr = backend.requestBytes(t, http.MethodPost, bidPath(1, proposer.pubkey), gloasHeader(MediaTypeJSON, "", 500), body)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), "relay says no")

		relay.OverrideHandleGetExecutionPayloadBid(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
		rr = backend.requestBytes(t, http.MethodPost, bidPath(1, proposer.pubkey), gloasHeader(MediaTypeJSON, "", 500), body)
		require.Equal(t, http.StatusBadGateway, rr.Code)

		relay.Server.Close()
		rr = backend.requestBytes(t, http.MethodPost, bidPath(1, proposer.pubkey), gloasHeader(MediaTypeJSON, "", 500), body)
		require.Equal(t, http.StatusBadGateway, rr.Code)
	})

	t.Run("request validation", func(t *testing.T) {
		backend := newTestBackend(t, 1, time.Second)
		relay := backend.relays[0]
		auth := proposer.signAuth(t, []byte(relay.RelayEntry.AuthData), 1)
		body := mustJSON(t, auth)
		path := bidPath(1, proposer.pubkey)

		cases := []struct {
			name   string
			path   string
			header http.Header
			body   []byte
			code   int
			errMsg string
		}{
			{name: "missing consensus version", path: path, header: withoutHeader(gloasHeader(MediaTypeJSON, "", 500), HeaderEthConsensusVersion), body: body, code: 400, errMsg: "Eth-Consensus-Version"},
			{name: "wrong consensus version", path: path, header: withHeader(gloasHeader(MediaTypeJSON, "", 500), HeaderEthConsensusVersion, "fulu"), body: body, code: 400, errMsg: "Eth-Consensus-Version"},
			{name: "missing timing headers", path: path, header: withoutHeader(gloasHeader(MediaTypeJSON, "", 500), HeaderTimeoutMs), body: body, code: 400, errMsg: "X-Timeout-Ms"},
			{name: "unsupported content type", path: path, header: gloasHeader("text/plain", "", 500), body: body, code: 415},
			{name: "empty body", path: path, header: gloasHeader(MediaTypeJSON, "", 500), body: nil, code: 400, errMsg: "missing request body"},
			{name: "malformed body", path: path, header: gloasHeader(MediaTypeJSON, "", 500), body: []byte(`{"message":{}}`), code: 400, errMsg: "invalid request body"},
			{name: "empty auth data", path: path, header: gloasHeader(MediaTypeJSON, "", 500), body: []byte(`{"message":{"data":"0x","slot":"1"},"signature":"` + hexutil.Encode(make([]byte, 96)) + `"}`), code: 400, errMsg: "data missing"},
			{name: "auth slot mismatch", path: bidPath(2, proposer.pubkey), header: gloasHeader(MediaTypeJSON, "", 500), body: body, code: 400, errMsg: "slot"},
			{name: "unknown auth data", path: path, header: gloasHeader(MediaTypeJSON, "", 500), body: mustJSON(t, proposer.signAuth(t, []byte("mev-boost.example"), 1)), code: 400, errMsg: "auth data"},
			{name: "signature by another key", path: path, header: gloasHeader(MediaTypeJSON, "", 500), body: mustJSON(t, newTestProposer(t).signAuth(t, []byte(relay.RelayEntry.AuthData), 1)), code: 401, errMsg: "signature"},
			{name: "invalid parent hash", path: fmt.Sprintf("/eth/v1/builder/execution_payload_bid/1/0x1234/%s/%s", testParentRoot, proposer.pubkey), header: gloasHeader(MediaTypeJSON, "", 500), body: body, code: 400},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				rr := backend.requestBytes(t, http.MethodPost, tc.path, tc.header, tc.body)
				require.Equal(t, tc.code, rr.Code, rr.Body.String())
				if tc.errMsg != "" {
					require.Contains(t, rr.Body.String(), tc.errMsg)
				}
			})
		}
		require.Equal(t, 0, relay.GetRequestCount(path), "rejected requests must not reach the relay")
	})

	t.Run("deadline already passed returns 204 without calling the relay", func(t *testing.T) {
		backend := newTestBackend(t, 1, time.Second)
		relay := backend.relays[0]
		auth := proposer.signAuth(t, []byte(relay.RelayEntry.AuthData), 1)
		header := gloasHeader(MediaTypeJSON, "", 500)
		header.Set(HeaderDateMilliseconds, strconv.FormatInt(time.Now().Add(-time.Second).UnixMilli(), 10))

		rr := backend.requestBytes(t, http.MethodPost, bidPath(1, proposer.pubkey), header, mustJSON(t, auth))
		require.Equal(t, http.StatusNoContent, rr.Code)
		require.Equal(t, 0, relay.GetRequestCount(bidPath(1, proposer.pubkey)))
	})

	t.Run("deadline is reduced by the margin", func(t *testing.T) {
		backend := newTestBackend(t, 1, time.Second)
		relay := backend.relays[0]
		auth := proposer.signAuth(t, []byte(relay.RelayEntry.AuthData), 1)

		var fwdTimeout int
		relay.OverrideHandleGetExecutionPayloadBid(func(w http.ResponseWriter, req *http.Request) {
			fwdTimeout, _ = strconv.Atoi(req.Header.Get(HeaderTimeoutMs))
			w.WriteHeader(http.StatusNoContent)
		})

		rr := backend.requestBytes(t, http.MethodPost, bidPath(1, proposer.pubkey), gloasHeader(MediaTypeJSON, "", 500), mustJSON(t, auth))
		require.Equal(t, http.StatusNoContent, rr.Code)
		require.LessOrEqual(t, fwdTimeout, 450)
		require.Greater(t, fwdTimeout, 400)
	})

	t.Run("advertised timeout never exceeds the relay client timeout", func(t *testing.T) {
		backend := newTestBackend(t, 1, 300*time.Millisecond)
		relay := backend.relays[0]
		auth := proposer.signAuth(t, []byte(relay.RelayEntry.AuthData), 1)

		var fwdTimeout int
		relay.OverrideHandleGetExecutionPayloadBid(func(w http.ResponseWriter, req *http.Request) {
			fwdTimeout, _ = strconv.Atoi(req.Header.Get(HeaderTimeoutMs))
			w.WriteHeader(http.StatusNoContent)
		})

		rr := backend.requestBytes(t, http.MethodPost, bidPath(1, proposer.pubkey), gloasHeader(MediaTypeJSON, "", 1000), mustJSON(t, auth))
		require.Equal(t, http.StatusNoContent, rr.Code)
		require.LessOrEqual(t, fwdTimeout, 300)
		require.Greater(t, fwdTimeout, 250)
	})

	t.Run("deadline is capped at late_in_slot_time_ms into the slot", func(t *testing.T) {
		backend := newTestBackend(t, 1, 3*time.Second) // slot 1 starts now, late_in_slot_time_ms is 2000
		relay := backend.relays[0]
		auth := proposer.signAuth(t, []byte(relay.RelayEntry.AuthData), 1)

		var fwdTimeout int
		relay.OverrideHandleGetExecutionPayloadBid(func(w http.ResponseWriter, req *http.Request) {
			fwdTimeout, _ = strconv.Atoi(req.Header.Get(HeaderTimeoutMs))
			w.WriteHeader(http.StatusNoContent)
		})

		rr := backend.requestBytes(t, http.MethodPost, bidPath(1, proposer.pubkey), gloasHeader(MediaTypeJSON, "", 10_000), mustJSON(t, auth))
		require.Equal(t, http.StatusNoContent, rr.Code)
		require.LessOrEqual(t, fwdTimeout, 2000)
		require.Greater(t, fwdTimeout, 1000)
	})

	t.Run("timing games poll the relay until the deadline and return the latest bid", func(t *testing.T) {
		backend := newTestBackend(t, 1, time.Second)
		relay := backend.relays[0]
		backend.boost.relayConfigs[0].EnableTimingGames = true
		backend.boost.relayConfigs[0].FrequencyGetHeaderMs = 40
		auth := proposer.signAuth(t, []byte(relay.RelayEntry.AuthData), 1)

		var mu sync.Mutex
		var value uint64
		relay.OverrideHandleGetExecutionPayloadBid(func(w http.ResponseWriter, _ *http.Request) {
			mu.Lock()
			value++
			v := value
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(gloasAPI.ExecutionPayloadBidResponse{Version: "gloas", Data: relay.MakeExecutionPayloadBid(v, 0, 1, testParentHash, testParentRoot, testParentHash)})
		})

		rr := backend.requestBytes(t, http.MethodPost, bidPath(1, proposer.pubkey), gloasHeader(MediaTypeJSON, "", 300), mustJSON(t, auth))
		require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		count := relay.GetRequestCount(bidPath(1, proposer.pubkey))
		require.Greater(t, count, 1)
		var bid gloasAPI.ExecutionPayloadBidResponse
		require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &bid))
		require.Equal(t, phase0.Gwei(count), bid.Data.Message.Value, "the last poll's bid must be returned")
	})
}

func TestSubmitBuilderPreferences(t *testing.T) {
	proposer := newTestProposer(t)
	path := "/eth/v1/builder/builder_preferences/" + proposer.pubkey

	t.Run("forwards to the matching relay and passes 202 through", func(t *testing.T) {
		backend := newTestBackend(t, 2, time.Second)
		setDistinctAuthData(backend)
		req := &builderApiGloas.BuilderPreferencesRequest{
			Preferences: &builderApiGloas.BuilderPreferences{MaxExecutionPayment: 1_000_000_000},
			Auth:        proposer.signAuth(t, []byte("relay-1"), 1),
		}
		body := mustJSON(t, req)

		var received []byte
		backend.relays[1].OverrideHandleSubmitBuilderPreferences(func(w http.ResponseWriter, r *http.Request) {
			received, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusAccepted)
		})

		rr := backend.requestBytes(t, http.MethodPost, path, gloasHeader(MediaTypeJSON, "", 500), body)
		require.Equal(t, http.StatusAccepted, rr.Code, rr.Body.String())
		require.Equal(t, body, received)
		require.Equal(t, 0, backend.relays[0].GetRequestCount(path))
	})

	t.Run("SSZ body", func(t *testing.T) {
		backend := newTestBackend(t, 1, time.Second)
		req := &builderApiGloas.BuilderPreferencesRequest{
			Preferences: &builderApiGloas.BuilderPreferences{MaxExecutionPayment: 5},
			Auth:        proposer.signAuth(t, []byte(backend.relays[0].RelayEntry.AuthData), 1),
		}
		body, err := req.MarshalSSZ()
		require.NoError(t, err)
		rr := backend.requestBytes(t, http.MethodPost, path, gloasHeader(MediaTypeOctetStream, "", 500), body)
		require.Equal(t, http.StatusAccepted, rr.Code, rr.Body.String())
	})

	t.Run("request validation", func(t *testing.T) {
		backend := newTestBackend(t, 1, time.Second)
		data := []byte(backend.relays[0].RelayEntry.AuthData)
		mk := func(auth *builderApiGloas.SignedBuilderRequestAuth) []byte {
			return mustJSON(t, &builderApiGloas.BuilderPreferencesRequest{Preferences: &builderApiGloas.BuilderPreferences{MaxExecutionPayment: 1}, Auth: auth})
		}
		cases := []struct {
			name   string
			header http.Header
			body   []byte
			code   int
			errMsg string
		}{
			{name: "missing consensus version", header: withoutHeader(gloasHeader(MediaTypeJSON, "", 500), HeaderEthConsensusVersion), body: mk(proposer.signAuth(t, data, 1)), code: 400},
			{name: "slot already passed", header: gloasHeader(MediaTypeJSON, "", 500), body: mk(proposer.signAuth(t, data, 0)), code: 400, errMsg: "already passed"},
			{name: "unknown auth data", header: gloasHeader(MediaTypeJSON, "", 500), body: mk(proposer.signAuth(t, []byte("other"), 1)), code: 400, errMsg: "auth data"},
			{name: "bad signature", header: gloasHeader(MediaTypeJSON, "", 500), body: mk(newTestProposer(t).signAuth(t, data, 1)), code: 401},
			{name: "missing preferences", header: gloasHeader(MediaTypeJSON, "", 500), body: []byte(`{"auth":` + string(mustJSON(t, proposer.signAuth(t, data, 1))) + `}`), code: 400},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				rr := backend.requestBytes(t, http.MethodPost, path, tc.header, tc.body)
				require.Equal(t, tc.code, rr.Code, rr.Body.String())
				if tc.errMsg != "" {
					require.Contains(t, rr.Body.String(), tc.errMsg)
				}
			})
		}
		require.Equal(t, 0, backend.relays[0].GetRequestCount(path))
	})
}

func TestSubmitSignedBeaconBlock(t *testing.T) {
	block := []byte(`{"message":{"slot":"1"},"signature":"0x00"}`)

	t.Run("202 when any relay accepts", func(t *testing.T) {
		backend := newTestBackend(t, 2, time.Second)
		backend.relays[0].OverrideHandleSubmitSignedBeaconBlock(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "not my bid", http.StatusBadRequest)
		})
		var received []byte
		backend.relays[1].OverrideHandleSubmitSignedBeaconBlock(func(w http.ResponseWriter, r *http.Request) {
			received, _ = io.ReadAll(r.Body)
			w.WriteHeader(http.StatusAccepted)
		})

		rr := backend.requestBytes(t, http.MethodPost, params.PathSubmitSignedBeaconBlock, gloasHeader(MediaTypeJSON, "", 500), block)
		require.Equal(t, http.StatusAccepted, rr.Code, rr.Body.String())
		require.Equal(t, block, received)
	})

	t.Run("502 when no relay accepts", func(t *testing.T) {
		backend := newTestBackend(t, 2, time.Second)
		for _, relay := range backend.relays {
			relay.OverrideHandleSubmitSignedBeaconBlock(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "not my bid", http.StatusBadRequest)
			})
		}
		rr := backend.requestBytes(t, http.MethodPost, params.PathSubmitSignedBeaconBlock, gloasHeader(MediaTypeJSON, "", 500), block)
		require.Equal(t, http.StatusBadGateway, rr.Code)
	})

	t.Run("request validation", func(t *testing.T) {
		backend := newTestBackend(t, 1, time.Second)
		rr := backend.requestBytes(t, http.MethodPost, params.PathSubmitSignedBeaconBlock, withoutHeader(gloasHeader(MediaTypeJSON, "", 500), HeaderEthConsensusVersion), block)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		rr = backend.requestBytes(t, http.MethodPost, params.PathSubmitSignedBeaconBlock, gloasHeader(MediaTypeJSON, "", 500), nil)
		require.Equal(t, http.StatusBadRequest, rr.Code)
		rr = backend.requestBytes(t, http.MethodPost, params.PathSubmitSignedBeaconBlock, gloasHeader("text/plain", "", 500), block)
		require.Equal(t, http.StatusUnsupportedMediaType, rr.Code)
		require.Equal(t, 0, backend.relays[0].GetRequestCount(params.PathSubmitSignedBeaconBlock))
	})
}

func TestValidateGloasRequest(t *testing.T) {
	auth := &builderApiGloas.SignedBuilderRequestAuth{Message: &builderApiGloas.BuilderRequestAuth{Data: []byte("x"), Slot: 1}}
	require.NoError(t, validateAuth(auth))
	require.ErrorIs(t, validateAuth(nil), gloasAPI.ErrNilMessage)
	require.ErrorIs(t, validateAuth(&builderApiGloas.SignedBuilderRequestAuth{}), gloasAPI.ErrNilMessage)
	require.ErrorIs(t, validateAuth(&builderApiGloas.SignedBuilderRequestAuth{Message: &builderApiGloas.BuilderRequestAuth{}}), gloasAPI.ErrEmptyAuthData)
	require.ErrorIs(t, validateAuth(&builderApiGloas.SignedBuilderRequestAuth{Message: &builderApiGloas.BuilderRequestAuth{Data: make([]byte, gloasAPI.MaxBuilderAuthDataSize+1)}}), gloasAPI.ErrAuthDataTooLarge)

	require.NoError(t, validatePreferences(&builderApiGloas.BuilderPreferencesRequest{Preferences: &builderApiGloas.BuilderPreferences{}, Auth: auth}))
	require.ErrorIs(t, validatePreferences(&builderApiGloas.BuilderPreferencesRequest{Auth: auth}), gloasAPI.ErrNilMessage)
	require.ErrorIs(t, validatePreferences(&builderApiGloas.BuilderPreferencesRequest{Preferences: &builderApiGloas.BuilderPreferences{}}), gloasAPI.ErrNilMessage)
}

func TestGloasEndpointsAreAdditive(t *testing.T) {
	backend := newTestBackend(t, 1, time.Second)
	rr := backend.request(t, http.MethodGet, params.PathStatus, http.Header{}, nil)
	require.Equal(t, http.StatusOK, rr.Code)
	rr = backend.requestBytes(t, http.MethodGet, bidPath(1, newTestProposer(t).pubkey), http.Header{}, nil)
	require.Equal(t, http.StatusMethodNotAllowed, rr.Code, "Gloas bid endpoint is POST only")
}

func withoutHeader(h http.Header, key string) http.Header {
	h.Del(key)
	return h
}

func withHeader(h http.Header, key, value string) http.Header {
	h.Set(key, value)
	return h
}
