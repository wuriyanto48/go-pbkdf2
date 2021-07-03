package p

import (
	"crypto/sha1"
	"testing"
)

func TestPbkdf2ReturnFalse(t *testing.T) {
	pass := NewPassword(sha1.New, 64, 64, 15000)
	hashed := pass.HashPassword("12345")
	cipherText := hashed.CipherText
	salt := hashed.Salt

	isValid := pass.VerifyPassword("1234", cipherText, salt)

	if isValid {
		t.Error("Verify Password was expected to return false : but result is ", isValid)
	}
}

func TestPbkdf2ReturnTrue(t *testing.T) {
	pass := NewPassword(sha1.New, 64, 64, 15000)
	hashed := pass.HashPassword("12345")
	cipherText := hashed.CipherText
	salt := hashed.Salt

	isValid := pass.VerifyPassword("12345", cipherText, salt)
	if !isValid {
		t.Error("Verify Password was expected to return true : but result is ", isValid)
	}
}

func BenchmarkPBKDF2HashOneThousandIterations(b *testing.B) {
	pass := NewPassword(sha1.New, 64, 64, 1000)
	for i := 0; i < b.N; i++ {
		pass.HashPassword("12345")
	}
}

func BenchmarkPBKDF2HashFifteenThousandIterations(b *testing.B) {
	pass := NewPassword(sha1.New, 64, 64, 15000)
	for i := 0; i < b.N; i++ {
		pass.HashPassword("12345")
	}
}
