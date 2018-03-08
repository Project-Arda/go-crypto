package crypto

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/Project-Arda/bgls"
	secp256k1 "github.com/btcsuite/btcd/btcec"
	"github.com/tendermint/ed25519"
	"github.com/tendermint/ed25519/extra25519"
	cmn "github.com/tendermint/tmlibs/common"
	"golang.org/x/crypto/ripemd160"
)

// An address is a []byte, but hex-encoded even in JSON.
// []byte leaves us the option to change the address length.
// Use an alias so Unmarshal methods (with ptr receivers) are available too.
type Address = cmn.HexBytes

func PubKeyFromBytes(pubKeyBytes []byte) (pubKey PubKey, err error) {
	err = cdc.UnmarshalBinaryBare(pubKeyBytes, &pubKey)
	return
}

//----------------------------------------

type PubKey interface {
	Address() Address
	Bytes() []byte
	VerifyBytes(msg []byte, sig Signature) bool
	Equals(PubKey) bool
}

//-------------------------------------

type AggregatablePubKey interface {
	Address() Address
	Bytes() []byte
	CheckAuthentication(sig AggregatableSignature) bool
	VerifyBytes(msg []byte, sig AggregatableSignature) bool
	Equals(AggregatablePubKey) bool

	// Assigns value into caller.
	Aggregate([]AggregatablePubKey) (PubKeyAltbn128, bool)
	VerifyAggregateSignature(msgs [][]byte, keys []AggregatablePubKey, sig AggregatableSignature, duplicates bool) bool
	VerifyMultiSignature(msg []byte, keys []AggregatablePubKey, sig AggregatableSignature) bool
}

//-------------------------------------

var _ PubKey = PubKeyEd25519{}

// Implements PubKeyInner
type PubKeyEd25519 [32]byte

func (pubKey PubKeyEd25519) Address() Address {
	// append type byte
	hasher := ripemd160.New()
	hasher.Write(pubKey.Bytes()) // does not error
	return Address(hasher.Sum(nil))
}

func (pubKey PubKeyEd25519) Bytes() []byte {
	bz, err := cdc.MarshalBinaryBare(pubKey)
	if err != nil {
		panic(err)
	}
	return bz
}

func (pubKey PubKeyEd25519) VerifyBytes(msg []byte, sig_ Signature) bool {
	// make sure we use the same algorithm to sign
	sig, ok := sig_.(SignatureEd25519)
	if !ok {
		return false
	}
	pubKeyBytes := [32]byte(pubKey)
	sigBytes := [64]byte(sig)
	return ed25519.Verify(&pubKeyBytes, msg, &sigBytes)
}

// For use with golang/crypto/nacl/box
// If error, returns nil.
func (pubKey PubKeyEd25519) ToCurve25519() *[32]byte {
	keyCurve25519, pubKeyBytes := new([32]byte), [32]byte(pubKey)
	ok := extra25519.PublicKeyToCurve25519(keyCurve25519, &pubKeyBytes)
	if !ok {
		return nil
	}
	return keyCurve25519
}

func (pubKey PubKeyEd25519) String() string {
	return fmt.Sprintf("PubKeyEd25519{%X}", pubKey[:])
}

func (pubKey PubKeyEd25519) Equals(other PubKey) bool {
	if otherEd, ok := other.(PubKeyEd25519); ok {
		return bytes.Equal(pubKey[:], otherEd[:])
	} else {
		return false
	}
}

//-------------------------------------

var _ PubKey = PubKeySecp256k1{}

// Implements PubKey.
// Compressed pubkey (just the x-cord),
// prefixed with 0x02 or 0x03, depending on the y-cord.
type PubKeySecp256k1 [33]byte

// Implements Bitcoin style addresses: RIPEMD160(SHA256(pubkey))
func (pubKey PubKeySecp256k1) Address() Address {
	hasherSHA256 := sha256.New()
	hasherSHA256.Write(pubKey[:]) // does not error
	sha := hasherSHA256.Sum(nil)

	hasherRIPEMD160 := ripemd160.New()
	hasherRIPEMD160.Write(sha) // does not error
	return Address(hasherRIPEMD160.Sum(nil))
}

func (pubKey PubKeySecp256k1) Bytes() []byte {
	bz, err := cdc.MarshalBinaryBare(pubKey)
	if err != nil {
		panic(err)
	}
	return bz
}

func (pubKey PubKeySecp256k1) VerifyBytes(msg []byte, sig_ Signature) bool {
	// and assert same algorithm to sign and verify
	sig, ok := sig_.(SignatureSecp256k1)
	if !ok {
		return false
	}

	pub__, err := secp256k1.ParsePubKey(pubKey[:], secp256k1.S256())
	if err != nil {
		return false
	}
	sig__, err := secp256k1.ParseDERSignature(sig[:], secp256k1.S256())
	if err != nil {
		return false
	}
	return sig__.Verify(Sha256(msg), pub__)
}

func (pubKey PubKeySecp256k1) String() string {
	return fmt.Sprintf("PubKeySecp256k1{%X}", pubKey[:])
}

func (pubKey PubKeySecp256k1) Equals(other PubKey) bool {
	if otherSecp, ok := other.(PubKeySecp256k1); ok {
		return bytes.Equal(pubKey[:], otherSecp[:])
	} else {
		return false
	}
}

//-------------------------------------

var _ AggregatablePubKey = PubKeyAltbn128{}

// Implements AggregatablePubKey.
type PubKeyAltbn128 struct {
	key bgls.Point2
}

func (pubKey PubKeyAltbn128) Address() Address {
	// append type byte
	hasher := ripemd160.New()
	hasher.Write(pubKey.Bytes()) // does not error
	return Address(hasher.Sum(nil))
}

func (pubKey PubKeyAltbn128) Bytes() []byte {
	return pubKey.key.Marshal()
}

func (pubKey PubKeyAltbn128) CheckAuthentication(sig_ AggregatableSignature) bool {
	// make sure we use the same algorithm to sign
	if sig, ok := sig_.(SignatureAltbn128); ok {
		return bgls.CheckAuthentication(bgls.Altbn128, pubKey.key, sig.sig)
	}
	return false
}

func (pubKey PubKeyAltbn128) VerifyBytes(msg []byte, sig_ AggregatableSignature) bool {
	// make sure we use the same algorithm to sign
	if sig, ok := sig_.(SignatureAltbn128); ok {
		return bgls.Verify(bgls.Altbn128, pubKey.key, msg, sig.sig)
	}
	return false
}

func (pubKey PubKeyAltbn128) String() string {
	return fmt.Sprintf("PubKeyAltbn128{%X}", pubKey.Bytes())
}

func (pubKey PubKeyAltbn128) Equals(other AggregatablePubKey) bool {
	if otherPt, ok := other.(PubKeyAltbn128); ok {
		return pubKey.key.Equals(otherPt.key)
	}
	return false
}

func convertPubKeysToBglsPoints(keys []AggregatablePubKey) ([]bgls.Point2, bool) {
	altbnKeys := make([]bgls.Point2, len(keys))
	for i := len(keys) - 1; i >= 0; i-- {
		if key, ok := keys[i].(PubKeyAltbn128); ok {
			altbnKeys[i] = key.key
		} else {
			return nil, false
		}
	}
	return altbnKeys, true
}

func (pubKey PubKeyAltbn128) Aggregate(keys []AggregatablePubKey) (PubKeyAltbn128, bool) {
	if altbnKeys, ok := convertPubKeysToBglsPoints(keys); ok {
		return PubKeyAltbn128{bgls.AggregateG2(altbnKeys)}, true
	}
	return PubKeyAltbn128{nil}, false
}

func (pubKey PubKeyAltbn128) VerifyAggregateSignature(msgs [][]byte, keys []AggregatablePubKey, sig AggregatableSignature, duplicates bool) bool {
	aggSig, ok := sig.(SignatureAltbn128)
	if !ok {
		return false
	}
	if altbnKeys, ok := convertPubKeysToBglsPoints(keys); ok {
		return bgls.VerifyAggregateSignature(bgls.Altbn128, aggSig.sig, altbnKeys, msgs, duplicates)
	}
	return false
}

func (pubKey PubKeyAltbn128) VerifyMultiSignature(msgs []byte, keys []AggregatablePubKey, sig AggregatableSignature) bool {
	aggSig, ok := sig.(SignatureAltbn128)
	if !ok {
		return false
	}
	if altbnKeys, ok := convertPubKeysToBglsPoints(keys); ok {
		return bgls.VerifyMultiSignature(bgls.Altbn128, aggSig.sig, altbnKeys, msgs)
	}
	return false
}
