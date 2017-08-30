package did

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

type SigAlg uint8

const (
	RSA SigAlg = iota
	ECDSA
	SM2
)

type Signature struct {
	Type       string `json:"type"`
	CreateTime string `json:"created"`
	Creator    string `json:"creator"`
	Value      []byte `json:"signatureValue"`
}

func ConstructSignature(id string, alg SigAlg, signature []byte) (*Signature, error) {
	st := new(Signature)

	i := strings.Index(id, "#")
	if i == -1 {
		st.Creator = id + "#key/1"
	} else {
		st.Creator = id
	}
	st.Value = signature

	switch alg {
	case RSA:
		st.Type = "RsaSignature2017"
		break
	case ECDSA:
		st.Type = "EcdsaKoblitzSignature2016"
		break
	case SM2:
		//st.Type = "SM2Signature"
		st.Type = "EcdsaKoblitzSignature2016"
		break
	default:
		return nil, errors.New("unknown signature algorithm")
	}

	t := time.Now()
	t = t.UTC()
	tstring := fmt.Sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ",
		t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
	st.CreateTime = tstring
	return st, nil
}
