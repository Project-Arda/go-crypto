package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/Project-Arda/bgls/bgls"
	"github.com/Project-Arda/bgls/curves"
	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type keyData struct {
	priv string
	pub  string
	addr string
}

var secpDataTable = []keyData{
	{
		priv: "a96e62ed3955e65be32703f12d87b6b5cf26039ecfa948dc5107a495418e5330",
		pub:  "02950e1cdfcb133d6024109fd489f734eeb4502418e538c28481f22bce276f248c",
		addr: "1CKZ9Nx4zgds8tU7nJHotKSDr4a9bYJCa3",
	},
}

func TestPubKeySecp256k1Address(t *testing.T) {
	for _, d := range secpDataTable {
		privB, _ := hex.DecodeString(d.priv)
		pubB, _ := hex.DecodeString(d.pub)
		addrBbz, _, _ := base58.CheckDecode(d.addr)
		addrB := Address(addrBbz)

		var priv PrivKeySecp256k1
		copy(priv[:], privB)

		pubT := priv.PubKey().(PubKeySecp256k1)
		pub := pubT[:]
		addr := priv.PubKey().Address()

		assert.Equal(t, pub, pubB, "Expected pub keys to match")
		assert.Equal(t, addr, addrB, "Expected addresses to match")
	}
}

func TestPubKeyInvalidDataProperReturnsEmpty(t *testing.T) {
	pk, err := PubKeyFromBytes([]byte("foo"))
	require.NotNil(t, err, "expecting a non-nil error")
	require.Nil(t, pk, "expecting an empty public key on error")
}

func TestAltbnMultisig(t *testing.T) {
	Tests, Size, Signers := 5, 32, 10
	for i := 0; i < Tests; i++ {
		msg := make([]byte, Size)
		rand.Read(msg)
		signers := make([]AggregatablePubKey, Signers)
		sigs := make([]AggregatableSignature, Signers)
		for j := 0; j < Signers; j++ {
			sk, vk, _ := bgls.KeyGen(curves.Altbn128)
			sigs[j] = PrivKeyAltbn128{sk}.Sign(msg)
			signers[j] = PubKeyAltbn128{vk}
		}
		aggSig, _ := new(SignatureAltbn128).Aggregate(sigs)
		aggSigner, _ := new(PubKeyAltbn128).Aggregate(signers)
		require.True(t, signers[0].VerifyMultiSignature(msg, signers, aggSig), "Verify Multisignature failed.")
		require.True(t, aggSigner.VerifyBytes(msg, aggSig), "Verify Multisignature failed.")
		rand.Read(msg)
		require.False(t, signers[0].VerifyMultiSignature(msg, signers, aggSig), "Verify Multisignature succeeded on incorrect message.")
		require.False(t, aggSigner.VerifyBytes(msg, aggSig), "Verify Multisignature failed.")
	}
}

func TestAltbnAggsig(t *testing.T) {
	N, Size := 6, 32
	msgs := make([][]byte, N)
	signers := make([]AggregatablePubKey, N)
	sigs := make([]AggregatableSignature, N)
	var lastAuth AggregatableSignature = nil
	for i := 0; i < N; i++ {
		msgs[i] = make([]byte, Size)
		rand.Read(msgs[i])
		sk, vk, _ := bgls.KeyGen(curves.Altbn128)
		privKey := PrivKeyAltbn128{sk}
		sig := privKey.Sign(msgs[i])
		signers[i] = PubKeyAltbn128{vk}
		sigs[i] = sig

		pubKey := privKey.PubKey()
		require.True(t, pubKey.Equals(signers[i]), "Copies of the same public key don't equal itself")
		lastAuth = privKey.Authenticate()
		require.True(t, pubKey.CheckAuthentication(lastAuth), "Creating Authentication failed")
	}
	for i := 0; i < (N - 1); i++ {
		require.False(t, signers[i].CheckAuthentication(lastAuth), "Creating Authentication suceeded on wrong key")
	}
	aggSig, _ := new(SignatureAltbn128).Aggregate(sigs)
	require.True(t, signers[0].VerifyAggregateSignature(msgs, signers, aggSig), "Verify Aggregate Signature failed.")
}
