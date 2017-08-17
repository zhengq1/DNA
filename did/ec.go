package did

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

type ECPrivateKey struct {
	ecdsa.PrivateKey
}

func (p *ECPrivateKey) Sign(msg []byte) ([]byte, error) {
	h := sha256.Sum256(msg)

	r, s, err := ecdsa.Sign(rand.Reader, &p.PrivateKey, h[:])
	if err != nil {
		return nil, err
	}

	return append(r.Bytes(), s.Bytes()...), nil
}

type ECPubKey struct {
	ecdsa.PublicKey
}

func (p *ECPubKey) Verify(msg, sig []byte) bool {
	h := sha256.Sum256(msg)
	l := len(sig) / 2
	return ecdsa.Verify(
		&p.PublicKey,
		h[:],
		new(big.Int).SetBytes(sig[:l]),
		new(big.Int).SetBytes(sig[l:]))
}

func (p *ECPubKey) Encode() []byte {
	//FIXME length should come from the curve parameter
	//TODO support compression mode
	buf := make([]byte, 65)
	buf[0] = 4
	x := p.X.Bytes()
	y := p.Y.Bytes()
	copy(buf[33-len(x):], x)
	copy(buf[65-len(y):], y)
	return buf
}

func (p *ECPubKey) Decode(key []byte) error {
	if p.Curve == nil {
		return errors.New("unknown curve")
	}
	//FIXME length should come from the curve parameter
	if len(key) != 65 {
		return errors.New("invalid public key length")
	}

	//TODO: support compression mode
	if key[0] != 4 {
		return errors.New("unsupported public key encoding")
	}

	p.X = new(big.Int).SetBytes(key[1:33])
	p.Y = new(big.Int).SetBytes(key[33:65])

	return nil
}

func (p *ECPubKey) parseKey(curveName string, key []byte) error {

	switch curveName {
	case "P-256":
		p.Curve = elliptic.P256()
		break
	default:
		return errors.New("unknown curve: " + curveName)
	}
	p.Decode(key)
	return nil
}
