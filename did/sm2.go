package did

import (
	"DNA/crypto"
)

func assert() {
	/*
		if crypto.AlgChoice != crypto.SM2 {
			panic("not using SM2 crypto algorithm")
		}
	*/
}

type SM2PrivateKey struct {
	SM2PublicKey
	D []byte
}

func (p *SM2PrivateKey) Sign(msg []byte) ([]byte, error) {
	assert()
	return crypto.Sign(p.D, msg)
}

type SM2PublicKey struct {
	crypto.PubKey
}

func (p *SM2PublicKey) Verify(msg, sig []byte) bool {
	assert()
	err := crypto.Verify(p.PubKey, msg, sig)
	if err != nil {
		return false
	}
	return true
}

func EncodeSM2PubKey(pk *SM2PublicKey) ([]byte, error) {
	return pk.PubKey.EncodePoint(true)
}

func DecodeSM2PubKey(data []byte) (*SM2PublicKey, error) {
	pk, err := crypto.DecodePoint(data)
	if err != nil {
		return nil, err
	}

	return &SM2PublicKey{
		PubKey: *pk,
	}, nil
}
