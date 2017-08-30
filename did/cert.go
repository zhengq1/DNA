package did

import (
	"encoding/json"
	"errors"
)

type Cert struct {
	ID       string     `json:"id"`
	CertHash string     `json:"certHash"`
	Sig      *Signature `json:"signature,omitempty"`
}

func CreateCert(did string, pk PubKey, sk PriKey, certHash string) ([]byte, error) {
	cert := Cert{
		ID:       did,
		CertHash: certHash,
		Sig:      nil,
	}
	raw, err := json.Marshal(cert)

	if err != nil {
		return nil, err
	}

	sig, err := sk.Sign(raw)
	if err != nil {
		return nil, err
	}

	cert.Sig, err = ConstructSignature(cert.ID, ECDSA, sig)
	if err != nil {
		return nil, err
	}
	return json.Marshal(cert)
}

func (p *Cert) VerifySignature(pk PubKey) error {
	if p.Sig == nil {
		return errors.New("Cert does not contain a signature")
	}

	msg, err := json.Marshal(Cert{
		ID:       p.ID,
		CertHash: p.CertHash,
		Sig:      nil,
	})
	if err != nil {
		return err
	}

	if pk.Verify(msg, p.Sig.Value) {
		return nil
	}

	return errors.New("verification failed")
}
