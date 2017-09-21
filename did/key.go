package did

import (
	"DNA/common"
	"DNA/common/log"
	"DNA/crypto"
	"strings"
)

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

func (p DNAPubKey) VerifyAddress(ID string) bool {
	i := strings.Index(ID, "#")
	if i == -1 {
		return false
	}

	j := strings.Index(ID, ":")
	if j == -1 {
		return false
	}
	str := ID[j+1 : i]
	j = strings.Index(str, ":")
	if j == -1 {
		return false
	}

	addr := str[j+1:]

	log.Fatal("[VerifyAddress] address: ", addr)

	pk := crypto.PubKey(p)
	strpk, err := pk.EncodePoint(true)
	if err != nil {
		return false
	}

	scripthash := []byte{byte(0x21)}
	scripthash = append(scripthash, strpk...)
	scripthash = append(scripthash, byte(0xac))

	hash160, err := common.ToCodeHash(scripthash)
	if err != nil {
		return false
	}

	address, err := hash160.ToAddress()
	if err != nil {
		return false
	}

	if address == addr {
		return true
	}

	return false
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
