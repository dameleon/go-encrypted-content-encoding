package main

import (
	"golang.org/x/crypto/hkdf"
	"io"
	"crypto/rand"
	"log"
	"github.com/enceve/crypto/dh/ecdh"
	"crypto/elliptic"
	"github.com/codegangsta/cli"
	"encoding/base64"
	"crypto/sha256"
)

const (
	PAD_SIZE = 2
	TAG_LENGTH = 16
	KEY_LENGTH = 16
	NONCE_LENGTH = 12
	SHA_256_LENGTH = 32
	SALT_LENGTH = 16
)

const auth = "hogehoge"

var keyHolder = make(map[[]byte][]byte)
var labelHolder = make(map[[]byte][]byte)

func main() {
	
}

type EncryptParams struct {
	buffer []byte
	salt []byte
	key []byte
	keyid []byte
	dh []byte
	authSecret []byte
	rs int
	padSize int
}

func Encrypt(p EncryptParams) {
	
}


func EncryptDeriveKey(p EncryptParams) ([]byte, []byte) {
	var secret []byte
	var context = []byte("")
	
	if p.key != nil {
		secret = p.key
	} else if p.dh {
			
	} else if p.keyid != nil {
		secret = keyHolder[p.keyid]
		if secret == nil {
			log.Fatal("undefined keyid")
		}
	}
	
	if p.authSecret != nil {
		auth := hkdf.New(sha256.New(), secret, p.authSecret, BuildInfo([]byte("auth"), []byte("")))
		auth.Read(secret)
	}
	
	var keyInfo, nonceInfo []byte
	
	switch p.padSize {
	case 2:
		keyInfo = BuildInfo([]byte("aesgcm"), context)
		nonceInfo = BuildInfo([]byte("nonce"), context)
	case 1:
		keyInfo = []byte("Content-Encoding: aesgcm128")
		nonceInfo = []byte("Content-Encoding: nonce")
	}
	
	hkdfKey := hkdf.New(sha256.New(), secret, p.salt, keyInfo)
	hkdfInfo := hkdf.New(sha256.New(), secret, p.salt, nonceInfo)
	key := make([]byte, KEY_LENGTH)
	info := make([]byte, NONCE_LENGTH)
	hkdfKey.Read(key)
	hkdfInfo.Read(info)
	return (key, info)
}

func DeriveDH(p EncryptParams, mode string, keyid, dh []byte) {
	var senderPubkey, receiverPubkey []byte
	
	switch mode {
	case "encrypt":
		senderPubkey = keyHolder[keyid]
		receiverPubkey = dh
	case "decrypt":
		senderPubkey = dh
		receiverPubkey = keyHolder[keyid]
	}
	
	if labelHolder[keyid] == nil {
		label
	}
}

func lengthPrefix() {
	
}

func BuildInfo(base, context []byte) []byte {
	return append([]byte("Content-Encoding: "), base, make([]byte, 1), context) 
}

func ExtractSalt(salt []byte) []byte {
	s, err := base64.URLEncoding.DecodeString(string(salt))
	if err != nil {
		log.Fatal(err)
	}
	if len(s) != KEY_LENGTH {
		log.Fatal("mismatch salt length")
	}
	return []byte(s)
}

func CreateSalt() ([]byte, error) {
	s := make([]byte, SALT_LENGTH)
	if _, err := io.ReadFull(rand.Reader, s); err != nil {
		return s, err
	}	
	return s, nil
}