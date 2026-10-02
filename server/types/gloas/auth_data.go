package gloas

import (
	"errors"
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common/hexutil"
)

var (
	ErrEmptyAuthData    = errors.New("auth data must not be empty")
	ErrAuthDataTooLarge = fmt.Errorf("auth data exceeds 4096 bytes")
)

func ParseAuthData(s string) ([]byte, error) {
	data := []byte(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		var err error
		if data, err = hexutil.Decode(s); err != nil {
			return nil, err
		}
	}
	if len(data) == 0 {
		return nil, ErrEmptyAuthData
	}
	if len(data) > 4096 {
		return nil, ErrAuthDataTooLarge
	}
	return data, nil
}
