// Wuriyanto 2017
// wuriyanto48@yahoo.co.id

package p

import (
	"bytes"
	"encoding/base64"
	"hash"
	"math/rand"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

type Password struct {
	Diggest    func() hash.Hash
	SaltSize   int
	KeyLen     int
	Iterations int
}

type HashResult struct {
	CipherText string
	Salt       string
}

func NewPassword(diggest func() hash.Hash, saltSize int, keyLen int, iter int) *Password {
	return &Password{
		Diggest:    diggest,
		SaltSize:   saltSize,
		KeyLen:     keyLen,
		Iterations: iter,
	}
}

func (p *Password) genSalt() string {
	saltBytes := make([]byte, p.SaltSize)
	rand.Seed(time.Now().UnixNano())
	rand.Read(saltBytes)
	return base64.StdEncoding.EncodeToString(saltBytes)
}

func (p *Password) HashPassword(password string) HashResult {
	saltString := p.genSalt()
	salt := bytes.NewBufferString(saltString).Bytes()
	df := pbkdf2.Key([]byte(password), salt, p.Iterations, p.KeyLen, p.Diggest)
	cipherText := base64.StdEncoding.EncodeToString(df)
	return HashResult{CipherText: cipherText, Salt: saltString}
}

func (p *Password) VerifyPassword(password, cipherText, salt string) bool {
	saltBytes := bytes.NewBufferString(salt).Bytes()
	df := pbkdf2.Key([]byte(password), saltBytes, p.Iterations, p.KeyLen, p.Diggest)
	newCipherText := base64.StdEncoding.EncodeToString(df)

	return p.slowEqual(cipherText, newCipherText)
}

// check per bit by applying bitwise XOR
// first, decode the base64 string to bytes
// for example
// 114  1110010
// 114  1110010
// ----------------- xor
//      000000
func (p *Password) slowEqual(cipherText, newCipherText string) bool {
	x, _ := base64.StdEncoding.DecodeString(cipherText)
	y, _ := base64.StdEncoding.DecodeString(newCipherText)
	diff := uint64(len(x)) ^ uint64(len(y))

	for i := 0; i < len(x) && i < len(y); i++ {
		diff |= uint64(x[i]) ^ uint64(y[i])
	}

	return diff == 0
}
