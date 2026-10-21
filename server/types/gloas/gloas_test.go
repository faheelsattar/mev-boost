package gloas

import (
	"testing"

	builderApiGloas "github.com/attestantio/go-builder-client/api/gloas"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/flashbots/go-boost-utils/bls"
	"github.com/flashbots/go-boost-utils/ssz"
	"github.com/stretchr/testify/require"
)

func testDomain(forkVersion phase0.Version) phase0.Domain {
	return ssz.ComputeDomain(DomainTypeBuilderRequestAuth, forkVersion, phase0.Root{})
}

func testSign(t *testing.T, msg *builderApiGloas.BuilderRequestAuth, sk *bls.SecretKey, domain phase0.Domain) phase0.BLSSignature {
	t.Helper()
	root, err := ssz.ComputeSigningRoot(msg, domain)
	require.NoError(t, err)
	var sig phase0.BLSSignature
	copy(sig[:], bls.SignatureToBytes(bls.Sign(sk, root[:])))
	return sig
}

func TestSignAndVerify(t *testing.T) {
	sk, pk, err := bls.GenerateNewKeypair()
	require.NoError(t, err)
	var pubkey phase0.BLSPubKey
	copy(pubkey[:], bls.PublicKeyToBytes(pk))

	domain := testDomain(phase0.Version{})
	require.Equal(t, [4]byte{0x0b, 0x00, 0x00, 0x01}, [4]byte(domain[:4]))

	msg := &builderApiGloas.BuilderRequestAuth{Data: []byte("relay.example.com"), Slot: 42}
	sig := testSign(t, msg, sk, domain)
	signed := &builderApiGloas.SignedBuilderRequestAuth{Message: msg, Signature: sig}

	ok, err := Verify(signed, pubkey, domain)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = Verify(signed, pubkey, testDomain(phase0.Version{0x01}))
	require.NoError(t, err)
	require.False(t, ok, "wrong fork version")

	tampered := &builderApiGloas.SignedBuilderRequestAuth{Message: &builderApiGloas.BuilderRequestAuth{Data: msg.Data, Slot: 43}, Signature: sig}
	ok, err = Verify(tampered, pubkey, domain)
	require.NoError(t, err)
	require.False(t, ok, "tampered slot")

	_, otherPk, err := bls.GenerateNewKeypair()
	require.NoError(t, err)
	var otherPubkey phase0.BLSPubKey
	copy(otherPubkey[:], bls.PublicKeyToBytes(otherPk))
	ok, err = Verify(signed, otherPubkey, domain)
	require.NoError(t, err)
	require.False(t, ok, "other key")

	_, err = Verify(&builderApiGloas.SignedBuilderRequestAuth{}, pubkey, domain)
	require.ErrorIs(t, err, ErrNilMessage)
}

func TestParseAuthData(t *testing.T) {
	data, err := ParseAuthData("relay-a")
	require.NoError(t, err)
	require.Equal(t, []byte("relay-a"), data)

	data, err = ParseAuthData("0x0102")
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2}, data)

	_, err = ParseAuthData("")
	require.ErrorIs(t, err, ErrEmptyAuthData)
	_, err = ParseAuthData("0x")
	require.ErrorIs(t, err, ErrEmptyAuthData)
	_, err = ParseAuthData("0xzz")
	require.Error(t, err)
	_, err = ParseAuthData(string(make([]byte, MaxBuilderAuthDataSize+1)))
	require.ErrorIs(t, err, ErrAuthDataTooLarge)
}

// TestDefaultAuthData uses the table from builder-specs specs/gloas/validator.md.
func TestDefaultAuthData(t *testing.T) {
	cases := map[string]string{
		"https://builder.example.com/":             "builder.example.com",
		"HTTPS://Builder.Example.com:443/bids?x=1": "builder.example.com",
		"https://builder.example.com:8080":         "builder.example.com",
		"https://user:pw@builder.example.com/":     "builder.example.com",
		"https://10.0.0.5:18550/eth/v1/builder":    "10.0.0.5",
		"https://[0:0:0:0:0:0:0:1]:8443/":          "[::1]",
		"https://[::ffff:192.0.2.1]/":              "[::ffff:c000:201]",
		// Relay URLs as mev-boost configures them, with the relay pubkey as userinfo.
		"https://0xac6e77dfe25ecd6110b8e780608cce0dab71fdd5ebea22a16c0205200f2f8e2e3ad3b71d3499c54ad14d6c21b41a37ae@boost-relay.flashbots.net": "boost-relay.flashbots.net",
		"http://localhost:18550": "localhost",
		// Additional RFC 5952 cases.
		"http://[2001:db8:0:0:1:0:0:1]/":    "[2001:db8::1:0:0:1]",
		"http://[2001:0db8::0001]/":         "[2001:db8::1]",
		"http://[0:0:0:0:0:0:0:0]/":         "[::]",
		"http://[2001:db8:0:1:1:1:1:1]/":    "[2001:db8:0:1:1:1:1:1]",
		"http://[1:0:0:2:0:0:0:3]/":         "[1:0:0:2::3]",
		"http://[fe80::1]:8080/":            "[fe80::1]",
		"http://[2001:DB8:AAAA:BBBB::CC]/":  "[2001:db8:aaaa:bbbb::cc]",
		"http://[::ffff:0.0.0.0]/":          "[::ffff:0:0]",
		"http://[::1234:5678:1.2.3.4]:443/": "[::1234:5678:102:304]",
	}
	for input, expected := range cases {
		t.Run(input, func(t *testing.T) {
			got, err := DefaultAuthData(input)
			require.NoError(t, err)
			require.Equal(t, expected, string(got))
		})
	}

	_, err := DefaultAuthData("https:///path")
	require.ErrorIs(t, err, ErrMissingHostname)
	_, err = DefaultAuthData("://bad")
	require.Error(t, err)
}
