// Wuriyanto 2017
// wuriyanto48@yahoo.co.id

package p

import(
	"math/rand"
	"encoding/base64"
	"hash"
	"golang.org/x/crypto/pbkdf2"
)

type Password struct {
	Diggest func() hash.Hash
	SaltSize int
	KeyLen int
	Iterations int
}

type HashResult struct {
	CipherText string
	Salt string
}

func NewPassword(diggest func() hash.Hash, saltSize int, keyLen int, iter int) *Password{
	return &Password{
		Diggest: diggest,
		SaltSize: saltSize,
		KeyLen: keyLen,
		Iterations: iter,
	}
}

func (p *Password) HashPassword(password string) HashResult{
	saltBytes := make([]byte, p.SaltSize)
	rand.Read(saltBytes)
	df := pbkdf2.Key([]byte(password), saltBytes, p.Iterations, p.KeyLen, p.Diggest)
	cipherText := base64.StdEncoding.EncodeToString(df)
	saltString := base64.StdEncoding.EncodeToString(saltBytes)
	return HashResult{CipherText: cipherText, Salt: saltString}
}

func (p *Password) VerifyPassword(password, cipherText, salt string) (bool, error){
	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return false, err
	}
	df := pbkdf2.Key([]byte(password), saltBytes, p.Iterations, p.KeyLen, p.Diggest)
	newCipherText := base64.StdEncoding.EncodeToString(df)
	valid := newCipherText == cipherText
	return valid, nil
}