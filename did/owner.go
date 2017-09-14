package did

import (
	"encoding/json"
	"errors"
)

type PriKey interface {
	Sign(message []byte) ([]byte, error)
}

type PubKey interface {
	Verify(message, signature []byte) bool
}

type OwnerKey struct {
	ID  string
	Key PubKey
}
type OwnerJSON struct {
	ID     string   `json:"id"`
	Type   []string `json:"type"`
	Expire string   `json:"expires,omitempty"`
	PubKey []byte   `json:"publicKeyBase64"`
	Curve  string   `json:"curve,omitempty"`
}

const (
	LABEL_ECDSA = "EcDsaPublicKey"
	LABEL_SM2   = "SM2PublicKey"
)

func (p *OwnerKey) UnmarshalJSON(data []byte) error {
	var key OwnerJSON
	json.Unmarshal(data, &key)

	var tmp PubKey = nil
	for _, t := range key.Type {
		switch t {
		case LABEL_ECDSA, LABEL_SM2:
			if CurveName() != key.Curve {
				return errors.New("unmatched curve")
			}
			pk, err := DecodeDNAKey(key.PubKey)
			if err != nil {
				return err
			}
			tmp = pk
			break
		}
	}

	if tmp == nil {
		return errors.New("unsupported public key")
	}

	p.Key = tmp
	p.ID = key.ID
	return nil
}

func (p *OwnerKey) MarshalJSON() ([]byte, error) {
	var jobj OwnerJSON
	jobj.ID = p.ID
	jobj.Type = append(jobj.Type, "CryptographicKey")

	switch v := p.Key.(type) {
	case DNAPubKey:
		buf, err := EncodeDNAKey(v)
		if err != nil {
			return nil, err
		}
		jobj.PubKey = buf
		jobj.Curve = CurveName()
		if jobj.Curve == "SM2" {
			jobj.Type = append(jobj.Type, LABEL_SM2)
		} else {
			jobj.Type = append(jobj.Type, LABEL_ECDSA)
		}

		break
	default:
		return nil, errors.New("unsupported public key")
	}

	return json.Marshal(jobj)
}
