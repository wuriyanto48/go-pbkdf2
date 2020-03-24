package main

import (
	"crypto/sha1"
	"flag"
	"fmt"
	"os"
	"strings"

	p "github.com/wuriyanto48/go-pbkdf2"
)

func main() {
	var (
		password    string
		cipherText  string
		salt        string
		saltSize    int
		keyLen      int
		iter        int
		showVersion bool
	)

	// sub command
	hashCommand := flag.NewFlagSet("hash", flag.ExitOnError)
	verifyCommand := flag.NewFlagSet("verify", flag.ExitOnError)

	hashCommand.StringVar(&password, "password", "", "-password mypass")
	hashCommand.IntVar(&saltSize, "saltSize", 512, "-saltSize 512")
	hashCommand.IntVar(&keyLen, "keyLen", 32, "-keyLen 32")
	hashCommand.IntVar(&iter, "iter", 1000, "-iter 1000")

	verifyCommand.StringVar(&password, "password", "", "-password mypass")
	verifyCommand.StringVar(&cipherText, "cipherText", "", "-cipherText mypass")
	verifyCommand.StringVar(&salt, "salt", "", "-salt xxxyyyy")
	verifyCommand.IntVar(&saltSize, "saltSize", 512, "-saltSize 512")
	verifyCommand.IntVar(&keyLen, "keyLen", 32, "-keyLen 32")
	verifyCommand.IntVar(&iter, "iter", 1000, "-iter 1000")

	flag.BoolVar(&showVersion, "version", false, "show version")

	flag.Usage = func() {
		fmt.Println("Usage:		go-pbkdf2 [options]")
		fmt.Println()
		fmt.Println("Hashing password: ")
		fmt.Println("go-pbkdf2 hash -password mypass -saltSize 512 -keyLen 32 -iter 1000")
		fmt.Println()
		fmt.Println("Verify Cipher text: ")
		fmt.Println("go-pbkdf2 verify -password mypass -cipherText myhashedpass -salt xxxyyyy -saltSize 512 -keyLen 32 -iter 1000")
		fmt.Println()
		fmt.Println("Options:")
		fmt.Println("-password		password that will be hash")
		fmt.Println("-salt			password's salt")
		fmt.Println("-cipherText		cipherText generated from password")
		fmt.Println("-saltSize 		salt size eg: 16")
		fmt.Println("-keyLen 		key len  eg: 512")
		fmt.Println("-iter 			iterations length eg: 15000")
		fmt.Println("-version		show version")

	}

	flag.Parse()

	if showVersion {
		fmt.Printf("version %s\n", "v0.0.0")
		os.Exit(0)
	}

	if len(os.Args) < 2 {
		fmt.Println("required sub command")
		os.Exit(1)
	}

	if !strings.Contains(os.Args[1], "version") {
		switch os.Args[1] {
		case "hash":
			hashCommand.Parse(os.Args[2:])
		case "verify":
			verifyCommand.Parse(os.Args[2:])
		default:
			fmt.Printf("invalid sub command %s\n", os.Args[1])
			os.Exit(1)
		}
	}

	if hashCommand.Parsed() {
		pass := p.NewPassword(sha1.New, saltSize, keyLen, iter)
		hashed := pass.HashPassword(password)
		fmt.Println("ciphertext : ", hashed.CipherText)
		fmt.Println("salt : ", hashed.Salt)
		os.Exit(0)
	}

	if verifyCommand.Parsed() {
		pass := p.NewPassword(sha1.New, saltSize, keyLen, iter)

		isValid := pass.VerifyPassword(password, cipherText, salt)

		if !isValid {
			fmt.Println("password did not match")
			os.Exit(0)
		}

		fmt.Println("password match")
		os.Exit(0)
	}
}
