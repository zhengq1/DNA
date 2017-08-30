package did

import (
	//"crypto/sha256"
	"errors"
	"fmt"
	//"math/big"
	"strings"
	//"github.com/tv42/base58"
)

const (
	method = "gyi"
)

/*
func GenerateDID(pk *ECPubKey, sk *ECPrivateKey) (string, []byte, error) {
	digest := sha256.Sum256(pk.Encode())
	v := make([]byte, 0)
	v = base58.EncodeBig(v, new(big.Int).SetBytes(digest[:]))
	id := fmt.Sprintf("did:%s:%s", method, v)
	ido, err := CreateDDO(id, pk, sk, nil, nil)
	if err != nil {
		return "", nil, err
	}
	return id, ido, nil
}
*/

func ConstructDID(idString string) string {
	return fmt.Sprintf("did:%s:%s", method, idString)
}

func DIDPath(id string) (string, error) {
	i := strings.Index(id, "/")
	if i > 0 {
		id = id[:i+1]
	}

	i = strings.Index(id, "#")
	if i > 0 {
		id = id[:i+1]
	}

	if strings.Count(id, ":") < 2 {
		return "", errors.New("invalid DID format")
	}

	return strings.Replace(id, ":", "/", 2) + "/", nil
}
