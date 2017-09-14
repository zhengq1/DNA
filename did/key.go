package did

import "DNA/crypto"

func CurveName() string {
	if crypto.AlgChoice == crypto.SM2 {
		return "SM2"
	} else {
		return "EcdsaP256r1"
	}
}

type DNAPriKey []byte

func (p DNAPriKey) Sign(message []byte) ([]byte, error) {
	return crypto.Sign([]byte(p), message)
}

type DNAPubKey crypto.PubKey

func (p DNAPubKey) Verify(message, signature []byte) bool {
	err := crypto.Verify(crypto.PubKey(p), message, signature)
	if err != nil {
		return false
	}

	return true
}

func EncodeDNAKey(k DNAPubKey) ([]byte, error) {
	key := crypto.PubKey(k)
	return key.EncodePoint(true)
}

func DecodeDNAKey(b []byte) (key DNAPubKey, err error) {
	k, err := crypto.DecodePoint(b)
	if err != nil {
		return
	}

	key = DNAPubKey(*k)
	return
}
