[![Build Status](https://travis-ci.org/wuriyanto48/go-pbkdf2.svg?branch=master)](https://travis-ci.org/wuriyanto48/go-pbkdf2)

# GO PBKDF2

PBKDF2 (Password-Based Key Derivation Function 2) https://en.wikipedia.org/wiki/PBKDF2

**This Implementation Based On**
Package pbkdf2 implements the key derivation function PBKDF2 as defined in RFC 2898 / PKCS #5 v2.0.
https://godoc.org/golang.org/x/crypto/pbkdf2

# USAGE

- **get first:**

```shell
go get github.com/wuriyanto48/go-pbkdf2
```

- **Hash a Password**
```go
package main

import(
	"fmt"
	"crypto/sha1"
	"github.com/wuriyanto48/go-pbkdf2"
)

func main(){
	pass := p.NewPassword(sha1.New, 8, 32,15000)
	hashed := pass.HashPassword("123456")
	fmt.Println(hashed.CipherText)
	fmt.Println(hashed.Salt)
}
```

- **Verify a Password**
```go
package main

import(
	"fmt"
	"crypto/sha1"
	"github.com/wuriyanto48/go-pbkdf2"
)

func main(){
	pass := p.NewPassword(sha1.New, 8, 32,15000)
	hashed := pass.HashPassword("123456")
	fmt.Println(hashed.CipherText)
	fmt.Println(hashed.Salt)

	isValid := pass.VerifyPassword("123456", hashed.CipherText, hashed.Salt)

	fmt.Println(isValid)
}
```

# Doc

- **func NewPassword**
	```go
	func NewPassword(func() hash.Hash, saltSize int, keyLen int, iterations int) *Password
	```
	the drafted v2.1 specification allows use of all five FIPS Approved
	Hash Functions SHA-1, SHA-224, SHA-256, SHA-384 and SHA-512 for HMAC. To
	choose, you can pass the `New` functions from the different SHA packages to
	pbkdf2.Key.

- **func HashPassword**
	```go
	func HashPassword("123456")
	```
	this function returning HashResult(struct) Which has two fields, CiphertText and Salt

- **func VerifyPassword**
	```go
	func VerifyPassword("123456", hashed.CipherText, hashed.Salt) (bool)
	```
	this function returning true if your password is valid and false otherwise
	
	
	
	##
	
	Wuriyanto Musobar 2017
