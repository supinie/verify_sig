package lib

import (
	"crypto/sha256"
    "crypto/x509"
	"encoding/pem"
    "encoding/asn1"
    "errors"
	"fmt"
	"io"
	"os"
    "math/big"

    "golang.org/x/crypto/cryptobyte"
    asn1_cryptobytes "golang.org/x/crypto/cryptobyte/asn1"
)

type publicKey struct {
    N *big.Int
    E int
}

// Get_hash takes a filename as a string and calculates the sha256 sum,
// outputting it as a byte slice.
func Get_hash(filename string) ([]byte, error) {
    file, err := os.Open(filename)
    if err != nil {
        fmt.Println(err)
        empty := make([]byte, 0)
        return empty, err
    }
    defer file.Close()

    file_hash := sha256.New()
    _, err = io.Copy(file_hash, file)
    if err != nil {
        fmt.Println(err)
        empty := make([]byte, 0)
        return empty, err
    }

    return file_hash.Sum(nil), err
}

// load_pem takes a filename of a PEM format certificate as a string, and
// outputs it as a DER encoded ASN.1 byte slice.
func load_pem(cert_filename string) ([]byte, error) {
    pem_bytes, err := os.ReadFile("certs/" + cert_filename)
    var empty_return []byte
    if err != nil {
        fmt.Println(err)
        return empty_return, err
    }

    der_block, _ := pem.Decode(pem_bytes)
    if der_block == nil {
        fmt.Println("Failed to decode PEM cert. Please check that it is a valid certificate.")
        return empty_return, err
    } else if der_block.Type != "CERTIFICATE" {
        fmt.Println("Please ensure you are passing a PEM certificate.")
        return empty_return, err
    }
    return der_block.Bytes, err
}

// Check_signature handles the heavy lifting of verifying the given signature against
// the given certificate. It outputs an integer, 1 if the verification is correct, and 
// 0 if the signature does not match or an error occurs.
func Check_signature(cert_filename string, signature, file_hash []byte) (int, error) {
    der_bytes, err := load_pem(cert_filename)
    if err != nil {
        fmt.Println(err)
        return 0, err
    }
    cert, err := x509.ParseCertificate(der_bytes)
    if err != nil {
        fmt.Println(err)
        return 0, err
    }
    if cert.SignatureAlgorithm.String() == "SHA256-RSA" {
        pk, err := extract_pk(der_bytes)
        if err != nil {
            return 0, err
        }

        signature_bigint := new(big.Int).SetBytes(signature)
        big_E := new(big.Int).SetInt64(int64(pk.E))
        decrypted_signature := new(big.Int).Exp(signature_bigint, big_E, pk.N)

        mod_len := (pk.N.BitLen() + 7) / 8
        hash_len := len(file_hash)

        decrypted_sig_bytes := decrypted_signature.FillBytes(make([]byte, mod_len))

        match := int((uint32(decrypted_sig_bytes[0]^0) - 1) >> 31)  // comparing bytes
        match &= int((uint32(decrypted_sig_bytes[1]^1) - 1) >> 31)

        if len(decrypted_sig_bytes[mod_len - hash_len:mod_len]) != hash_len {
            fmt.Println("Mismatching hash and signature lengths")
            return 0, err
        }
        var b byte
        // compare two byte slices
        for i := 0; i < hash_len; i++ {
            b |= decrypted_sig_bytes[mod_len - hash_len:mod_len][i] ^ file_hash[i] 
        }
        match &= int((uint32(b^0) - 1) >> 31)

        sha256_prefix := []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}

        if len(decrypted_sig_bytes[mod_len - (len(sha256_prefix) + hash_len):mod_len - hash_len]) != len(sha256_prefix) {
            fmt.Println("Mismatching hash lengths")
            return 0, err
        }

        for i := 0; i < len(sha256_prefix); i++ {
            b |= decrypted_sig_bytes[mod_len - (len(sha256_prefix) + hash_len):mod_len - hash_len][i] ^ sha256_prefix[i]
        }
        match &= int((uint32(b^0) - 1) >> 31)

        match &= int((uint32(decrypted_sig_bytes[mod_len - (len(sha256_prefix) + hash_len) - 1]^0) - 1) >> 31)

        for i := 2; i < mod_len - (len(sha256_prefix) + hash_len) - 1; i++ {
            match &= int((uint32(decrypted_sig_bytes[i]^0xff) - 1) >> 31)
        }

        if match == 1 {
            return match, err
        }
        return 0, errors.New("Signature does not match certificate")
    } else {
        return 0, errors.New("Certificate not using SHA256 with RSA, ending check.")
    }
}

// extract_pk takes a DER encoded ASN.1 byte slice of a certificate and extracts the
// public key, outputting it as publicKey(N: big.Int, E: int).
func extract_pk(der_bytes []byte) (publicKey, error) {
    err_pk := publicKey{big.NewInt(-1), -1}
    asn_bytes := cryptobyte.String(der_bytes)
    success := asn_bytes.ReadASN1(&asn_bytes, asn1_cryptobytes.SEQUENCE)
    if !success {
        return err_pk, errors.New("Malformed x509 certificate.")
    }
	success = asn_bytes.ReadASN1(&asn_bytes, asn1_cryptobytes.SEQUENCE)
    if !success {
        return err_pk, errors.New("Malformed x509 certificate.")
    }
	var version int
	success = asn_bytes.ReadOptionalASN1Integer(&version, asn1_cryptobytes.Tag(0).Constructed().ContextSpecific(), 0)
    if !success {
        return err_pk, errors.New("Malformed x509 certificate.")
    }
	serial := new(big.Int)
	success = asn_bytes.ReadASN1Integer(serial)
    if !success {
        return err_pk, errors.New("Malformed x509 certificate.")
    }
	var temp cryptobyte.String
	success = asn_bytes.ReadASN1(&temp, asn1_cryptobytes.SEQUENCE)
    if !success {
        return err_pk, errors.New("Malformed x509 certificate.")
    }
	success = asn_bytes.ReadASN1Element(&temp, asn1_cryptobytes.SEQUENCE)
    if !success {
        return err_pk, errors.New("Malformed x509 certificate.")
    }
	success = asn_bytes.ReadASN1(&temp, asn1_cryptobytes.SEQUENCE)
    if !success {
        return err_pk, errors.New("Malformed x509 certificate.")
    }
	success = asn_bytes.ReadASN1Element(&temp, asn1_cryptobytes.SEQUENCE)
    if !success {
        return err_pk, errors.New("Malformed x509 certificate.")
    }
	var spki cryptobyte.String
	success = asn_bytes.ReadASN1Element(&spki, asn1_cryptobytes.SEQUENCE)
    if !success {
        return err_pk, errors.New("Malformed x509 certificate.")
    }
	success = spki.ReadASN1(&spki, asn1_cryptobytes.SEQUENCE)
    if !success {
        return err_pk, errors.New("Malformed x509 certificate.")
    }
	success = spki.ReadASN1(&temp, asn1_cryptobytes.SEQUENCE)
    if !success {
        return err_pk, errors.New("Malformed x509 certificate.")
    }
	var spk asn1.BitString
	success = spki.ReadASN1BitString(&spk)
    if !success {
        return err_pk, errors.New("Malformed x509 certificate.")
    }
    spk_der := cryptobyte.String(spk.RightAlign())
    success = spk_der.ReadASN1(&spk_der, asn1_cryptobytes.SEQUENCE)
    if !success {
        return err_pk, errors.New("Malformed x509 certificate, malformed public key.")
    }
    pk := publicKey{N: big.NewInt(0), E: 0}
    success = spk_der.ReadASN1Integer(pk.N)
    if !success {
        return err_pk, errors.New("Malformed x509 certificate, invalid modulus.")
    }
    success = spk_der.ReadASN1Integer(&pk.E)
    if !success {
        return err_pk, errors.New("Malformed x509 certificate, invalid exponent.")
    }
    
    return pk, nil
}


