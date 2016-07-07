package main

import (
	"golang.org/x/crypto/hkdf"
	"io"
	"crypto/rand"
	"log"
	"encoding/base64"
	"crypto/sha256"
	"bytes"
	"encoding/binary"
	"github.com/enceve/crypto/dh/ecdh"
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

var holder = NewKeyHolder()

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


func deriveKeyAndNonce(p EncryptParams, mode string) ([]byte, []byte) {
	var salt = extractSalt(p.salt)
	var secret, context = extractSecretAndContext(p, mode)
	var keyInfo, nonceInfo []byte
	
	switch p.padSize {
	case 2:
		keyInfo = BuildInfo([]byte("aesgcm"), context)
		nonceInfo = BuildInfo([]byte("nonce"), context)
	case 1:
		keyInfo = []byte("Content-Encoding: aesgcm128")
		nonceInfo = []byte("Content-Encoding: nonce")
	}
	hkdfKey := hkdf.New(sha256.New, secret, salt, keyInfo)
	hkdfNonce := hkdf.New(sha256.New, secret, salt, nonceInfo)
	key := make([]byte, KEY_LENGTH)
	nonce := make([]byte, NONCE_LENGTH)
	hkdfKey.Read(key)
	hkdfNonce.Read(nonce)
	return key, nonce
}

func extractSecretAndContext(p EncryptParams, mode string) ([]byte, []byte) {
	var secret []byte
	var context []byte
	
	if p.key != nil {
		secret = extractSalt(p.key)
	} else if p.dh != nil {
		secret, context = extractDH(p.keyid, p.dh, mode)
	} else if p.keyid != nil {
		var err error
		secret, _, err = holder.Get(p.keyid)
		if err != nil {
			log.Fatal("undefined keyid")
		}
	}
	if secret == nil {
		log.Fatal("null secret")
	}
	if p.authSecret != nil {
		var authSecret []byte
		if _, err := base64.URLEncoding.Decode(authSecret, p.authSecret); err != nil {
			log.Fatal("cannot decode authSecret")
		}
		auth := hkdf.New(sha256.New, secret, authSecret, BuildInfo([]byte("auth"), []byte{}))
		auth.Read(secret)
	}
	return secret, context
}

func extractDH(keyid, dh []byte, mode string) ([]byte, []byte) {
	key, label, err := holder.Get(keyid)
	if err != nil {
		log.Fatal("undefined keyid")
	}
	var senderPubkey, receiverPubkey []byte
	switch mode {
	case "encrypt":
		senderPubkey = key
		receiverPubkey = dh
	case "decrypt":
		senderPubkey = dh
		receiverPubkey = key
	}
	buf := bytes.Buffer{}
	buf.Write(label)
	buf.Write(lengthPrefix(receiverPubkey))
	buf.Write(lengthPrefix(senderPubkey))
	return ecdh.Curve25519().ComputeSecret(key, dh), buf.Bytes()
}

func lengthPrefix(b []byte) []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, uint16(len(b)))
	buf.Write(b)
	return buf.Bytes()
}

func BuildInfo(base, context []byte) []byte {
	buf := bytes.Buffer{}
	buf.Write([]byte("Content-Encoding: "))
	buf.Write(base)
	buf.Write(context)
	return buf.Bytes()
}

func extractSalt(salt []byte) []byte {
	var s []byte
	if _, err := base64.URLEncoding.Decode(s, salt); err != nil {
		log.Fatal(err)
	}
	if len(s) != KEY_LENGTH {
		log.Fatal("mismatch salt length")
	}
	return s
}

func CreateSalt() ([]byte, error) {
	s := make([]byte, SALT_LENGTH)
	if _, err := io.ReadFull(rand.Reader, s); err != nil {
		return s, err
	}	
	return s, nil
}

func encrypt(buf []byte, p EncryptParams) {
	var key, nonce = deriveKeyAndNonce(p, "encrypt")
	var rs = p.rs
}

