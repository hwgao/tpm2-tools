package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	tpmPath         = "/dev/tpmrm0"
	localKeyHandle  = 0x81010004
	deviceKeyHandle = 0x81010005
	defaultPassword = "\x01\x02\x03\x04"
	emptyPassword   = ""
)

var (
	defaultKeyParams = tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA1,
		Attributes: tpm2.FlagStorageDefault,
		RSAParameters: &tpm2.RSAParams{
			Symmetric: &tpm2.SymScheme{
				Alg:     tpm2.AlgAES,
				KeyBits: 128,
				Mode:    tpm2.AlgCFB,
			},
			KeyBits:     2048,
			ExponentRaw: 1<<16 + 1,
		},
	}
	pcrSelection7 = tpm2.PCRSelection{Hash: tpm2.AlgSHA1, PCRs: []int{7}}
)

func openTPM() io.ReadWriteCloser {
	if _, err := os.Stat(tpmPath); err == nil {
		// Use device tpm
		rw, err := tpm2.OpenTPM(tpmPath)
		if err != nil {
			log.Fatalf("Open TPM at %s failed: %s\n", tpmPath, err)
		}
		return rw
	}

	// Use tpm simulator
	simulator, err := simulator.Get()
	if err != nil {
		log.Fatalf("Simulator initialization failed: %v", err)
	}

	return simulator
}

func genEnrollKeypair() (string, error) {
	rw := openTPM()
	defer rw.Close()

	// Clear tpm2
	// err := tpm2.Clear(rw, tpm2.HandleLockout, tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession})
	// if err != nil {
	//     log.Fatalf("Clear failed: %v", err)
	// }

	// Create primary key
	parentHandle, _, err := tpm2.CreatePrimary(rw, tpm2.HandleOwner, pcrSelection7, emptyPassword, defaultPassword, defaultKeyParams)
	if err != nil {
		log.Fatalf("CreatePrimary failed: %s", err)
	}
	defer tpm2.FlushContext(rw, parentHandle)

	// Create keypair
	privateBlob, publicBlob, _, _, _, err := tpm2.CreateKey(rw, parentHandle, pcrSelection7, defaultPassword, defaultPassword, defaultKeyParams)
	if err != nil {
		log.Fatalf("CreateKey failed: %s", err)
	}

	// Load keypair to tpm
	keyHandle, _, err := tpm2.Load(rw, parentHandle, defaultPassword, publicBlob, privateBlob)
	if err != nil {
		log.Fatalf("Load failed: %s", err)
	}
	defer tpm2.FlushContext(rw, keyHandle)

	persistentHandle := tpmutil.Handle(localKeyHandle)
	// Evict persistent key, if there is one already (e.g. last test run failed).
	if err := tpm2.EvictControl(rw, emptyPassword, tpm2.HandleOwner, persistentHandle, persistentHandle); err != nil {
		log.Printf("(expected) EvictControl failed: %v", err)
	}

	// Make key persistent.
	if err := tpm2.EvictControl(rw, emptyPassword, tpm2.HandleOwner, keyHandle, persistentHandle); err != nil {
		log.Fatalf("EvictControl failed: %v", err)
	}

	// Read public key
	tpmPub, _, _, err := tpm2.ReadPublic(rw, keyHandle)
	if err != nil {
		log.Fatalf("ReadPublic failed: %s", err)
	}

	p, err := tpmPub.Key()
	if err != nil {
		log.Fatalf("tpmPub.Key() failed: %s", err)
	}
	log.Printf("tpmPub Size(): %d", p.(*rsa.PublicKey).Size())

	b, err := x509.MarshalPKIXPublicKey(p)
	if err != nil {
		log.Fatalf("Unable to convert public: %s", err)
	}

	kPubPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: b,
		},
	)
	log.Printf("PubPEM: \n%v", string(kPubPEM))

	return string(kPubPEM), nil
}

func persistDevicePrikey(priKeyPath string) error {
	data, err := ioutil.ReadFile(priKeyPath)
	if err != nil {
		log.Fatalf("Read private key file failed: %s", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		log.Fatalln("Decode private key failed")
	}

	pv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalln("Parse private key failed: %s", err)
	}

	rw := openTPM()
	defer rw.Close()

	// Create primary key
	parentHandle, _, err := tpm2.CreatePrimary(rw, tpm2.HandleOwner, pcrSelection7, emptyPassword, defaultPassword, defaultKeyParams)
	if err != nil {
		log.Fatalf("CreatePrimary failed: %s", err)
	}
	defer tpm2.FlushContext(rw, parentHandle)

	rp := tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagUserWithAuth | tpm2.FlagSign, // | tpm2.FlagDecrypt,
		RSAParameters: &tpm2.RSAParams{
			KeyBits:     2048,
			ExponentRaw: uint32(pv.PublicKey.E),
			ModulusRaw:  pv.PublicKey.N.Bytes(),
		},
	}

	rpriv := tpm2.Private{
		Type:      tpm2.AlgRSA,
		Sensitive: pv.Primes[0].Bytes(),
	}

	pubArea, err := rp.Encode()
	if err != nil {
		log.Fatalf("Public encoding failed: %s", err)
	}

	priArea, err := rpriv.Encode()
	if err != nil {
		log.Fatalf("Private encoding failed: %s", err)
	}

	emptyAuth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
	priInternal, err := tpm2.Import(rw, parentHandle, emptyAuth, pubArea, priArea, nil, nil, nil)
	if err != nil {
		log.Fatalf("Import failed: %s", err)
	}
	keyHandle, _, err := tpm2.Load(rw, parentHandle, emptyPassword, pubArea, priInternal)
	if err != nil {
		log.Fatalf("Load failed: %s", err)
	}
	defer tpm2.FlushContext(rw, keyHandle)

	persistentHandle := tpmutil.Handle(deviceKeyHandle)
	// Evict persistent key, if there is one already (e.g. last test run failed).
	if err := tpm2.EvictControl(rw, emptyPassword, tpm2.HandleOwner, persistentHandle, persistentHandle); err != nil {
		log.Printf("(expected) EvictControl failed: %v", err)
	}

	// Make key persistent.
	if err := tpm2.EvictControl(rw, emptyPassword, tpm2.HandleOwner, keyHandle, persistentHandle); err != nil {
		log.Fatalf("EvictControl failed: %v", err)
	}
	return nil
}
