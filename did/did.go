package did

import (
	"errors"
	"fmt"
	"strings"
)

const (
	method = "gyi"
)

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
