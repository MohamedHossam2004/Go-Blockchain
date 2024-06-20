package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"log"

	"golang.org/x/crypto/ripemd160"
)

const version = byte(0x00)
const walletFile = "wallet.dat"
const addressChecksumLen = 4

type Wallet struct {
    PrivateKey []byte
    PublicKey  []byte
}

func (w *Wallet) GetPrivateKey() *ecdsa.PrivateKey {
    privateKey, err := x509.ParseECPrivateKey(w.PrivateKey)
	if err != nil {
		log.Panic(err)
	}
    return privateKey
}

func (w *Wallet) GetPublicKey() *ecdsa.PublicKey {
    publicKey, err := x509.ParsePKIXPublicKey(w.PublicKey)
	if err != nil {
		log.Panic(err)
	}
    return publicKey.(*ecdsa.PublicKey)
}

func NewWallet() *Wallet {
	private, public:= newKeyPair()
	privateBytes, _ := x509.MarshalECPrivateKey(&private)
	wallet := Wallet{PrivateKey: privateBytes, PublicKey: public}

	return &wallet
}

func (w Wallet) GetAddress() []byte {
	pubKeyHash := HashPubKey(w.PublicKey)

	versionedPayload := append([]byte{version}, pubKeyHash...)
	checksum := checksum(versionedPayload)

	fullPayload := append(versionedPayload, checksum...)
	address := Base58Encode(fullPayload)

	return address
}

func HashPubKey(pubKey []byte) []byte {
	publicSHA256 := sha256.Sum256(pubKey)

	RIPEMD160Hasher := ripemd160.New()
	_, err := RIPEMD160Hasher.Write(publicSHA256[:])
	if err != nil {
		log.Panic(err)
	}
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)

	return publicRIPEMD160
}

func ValidateAddress(address string) bool {
	pubKeyHash := Base58Decode([]byte(address))
	actualChecksum := pubKeyHash[len(pubKeyHash)-addressChecksumLen:]
	version := pubKeyHash[0]
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-addressChecksumLen]
	targetChecksum := checksum(append([]byte{version}, pubKeyHash...))

	return bytes.Compare(actualChecksum, targetChecksum) == 0
}

func checksum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])

	return secondSHA[:addressChecksumLen]
}

func newKeyPair() (ecdsa.PrivateKey, []byte) {
	curve := elliptic.P256()
	private, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		log.Panic(err)
	}
	pubKey := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)

	return *private, pubKey
}


