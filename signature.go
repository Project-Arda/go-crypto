package crypto

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/Project-Arda/bgls/bgls"
	"github.com/Project-Arda/bgls/curves"
	. "github.com/tendermint/tmlibs/common"
)

func SignatureFromBytes(pubKeyBytes []byte) (pubKey Signature, err error) {
	err = cdc.UnmarshalBinaryBare(pubKeyBytes, &pubKey)
	return
}

//----------------------------------------

type Signature interface {
	Bytes() []byte
	IsZero() bool
	Equals(Signature) bool
}

//-------------------------------------

type AggregatableSignature interface {
	Bytes() []byte
	IsZero() bool
	Equals(AggregatableSignature) bool

	// Assigns value into caller.
	Aggregate([]AggregatableSignature) (AggregatableSignature, bool)
}

//-------------------------------------

var _ Signature = SignatureEd25519{}

// Implements Signature
type SignatureEd25519 [64]byte

func (sig SignatureEd25519) Bytes() []byte {
	bz, err := cdc.MarshalBinaryBare(sig)
	if err != nil {
		panic(err)
	}
	return bz
}

func (sig SignatureEd25519) IsZero() bool { return len(sig) == 0 }

func (sig SignatureEd25519) String() string { return fmt.Sprintf("/%X.../", Fingerprint(sig[:])) }

func (sig SignatureEd25519) Equals(other Signature) bool {
	if otherEd, ok := other.(SignatureEd25519); ok {
		return bytes.Equal(sig[:], otherEd[:])
	} else {
		return false
	}
}

func SignatureEd25519FromBytes(data []byte) Signature {
	var sig SignatureEd25519
	copy(sig[:], data)
	return sig
}

//-------------------------------------

var _ Signature = SignatureSecp256k1{}

// Implements Signature
type SignatureSecp256k1 []byte

func (sig SignatureSecp256k1) Bytes() []byte {
	bz, err := cdc.MarshalBinaryBare(sig)
	if err != nil {
		panic(err)
	}
	return bz
}

func (sig SignatureSecp256k1) IsZero() bool { return len(sig) == 0 }

func (sig SignatureSecp256k1) String() string { return fmt.Sprintf("/%X.../", Fingerprint(sig[:])) }

func (sig SignatureSecp256k1) Equals(other Signature) bool {
	if otherSecp, ok := other.(SignatureSecp256k1); ok {
		return bytes.Equal(sig[:], otherSecp[:])
	} else {
		return false
	}
}

//-------------------------------------

var _ AggregatableSignature = SignatureAltbn128{}

// Implements Aggregate Signature
type SignatureAltbn128 struct {
	sig curves.Point1
}

func (sig SignatureAltbn128) Bytes() []byte {
	return sig.sig.Marshal()
}

func (sig SignatureAltbn128) IsZero() bool {
	if sig.sig == nil {
		return false
	}
	x, y := sig.sig.ToAffineCoords()
	zero := big.NewInt(0)
	return x.Cmp(zero) != 0 && y.Cmp(zero) != 0
}

func (sig SignatureAltbn128) Equals(other AggregatableSignature) bool {
	if otherBn, ok := other.(SignatureAltbn128); ok {
		return sig.Equals(otherBn)
	} else {
		return false
	}
}

func (sig SignatureAltbn128) Aggregate(signatures []AggregatableSignature) (AggregatableSignature, bool) {
	altbnSigs := make([]curves.Point1, len(signatures))
	for i := len(signatures) - 1; i >= 0; i-- {
		if sig, ok := signatures[i].(SignatureAltbn128); ok {
			altbnSigs[i] = sig.sig
		} else {
			return nil, false
		}
	}
	return SignatureAltbn128{bgls.AggregateG1(altbnSigs)}, true
}
