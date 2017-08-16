package payload

import (
	"DNA/common/serialization"
	"DNA/crypto"
	. "DNA/errors"
	"errors"
	"io"
)

type IdentityUpdate struct {
	DID     []byte
	DDO     []byte
	Updater *crypto.PubKey
}

func (iu *IdentityUpdate) Data(version byte) []byte {
	return []byte{0}
}

func (iu *IdentityUpdate) Serialize(w io.Writer, version byte) error {
	err := serialization.WriteVarBytes(w, iu.DID)
	if err != nil {
		return NewDetailErr(err, ErrNoCode, "[IdentityUpdate], DID serialize failed.")
	}

	err = serialization.WriteVarBytes(w, iu.DDO)
	if err != nil {
		return NewDetailErr(err, ErrNoCode, "[IdentityUpdate], DDO serialize failed.")
	}

	iu.Updater.Serialize(w)

	return nil
}

func (iu *IdentityUpdate) Deserialize(r io.Reader, version byte) error {
	var err error

	iu.DID, err = serialization.ReadVarBytes(r)
	if err != nil {
		return NewDetailErr(errors.New("[IdentityUpdate], DID deserialize failed."), ErrNoCode, "")
	}

	iu.DDO, err = serialization.ReadVarBytes(r)
	if err != nil {
		return NewDetailErr(errors.New("[IdentityUpdate], DDO deserialize failed."), ErrNoCode, "")
	}

	iu.Updater = new(crypto.PubKey)
	err = iu.Updater.DeSerialize(r)
	if err != nil {
		return NewDetailErr(err, ErrNoCode, "[IdentityUpdate], updater Deserialize failed.")
	}

	return nil
}
