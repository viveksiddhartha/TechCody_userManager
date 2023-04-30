package utility

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/scrypt"
)

// SaltLength represents the length of the salt to generate.
const SaltLength = 5

// HashPassword generates a salted hash of the provided password using scrypt.
func HashPassword(password string) (string, error) {
	// Generate a random salt.
	salt := make([]byte, SaltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	// Hash the password using scrypt.
	hashedPassword, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}

	// Encode the salt and hashed password as hex strings and return the result.
	return hex.EncodeToString(salt) + ":" + hex.EncodeToString(hashedPassword), nil
}

// create function to convert the password to sha256 hash
func Sha256HexSumPassword(password string) (string, error) {
	//convert the password string to byte slice
	passwordBytes := []byte(password)
	//generate a new sha256 hash.Hash
	hash := sha256.New()
	//write the passwordBytes to the hash
	_, err := hash.Write(passwordBytes)
	if err != nil {
		return "", err
	}
	//get the sha256 hash sum
	sum := hash.Sum(nil)
	//convert the sha256 hash sum to a hex string
	hexSum := hex.EncodeToString(sum)
	//return the hex string
	return hexSum, nil
}
