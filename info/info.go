package info

import (
	"bytes"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
)

func IssuerName(cert *x509.Certificate) string {
	return cert.Issuer.String()
}

func IssuerNameHash(cert *x509.Certificate) string {
	sum := sha1.Sum(cert.RawIssuer)
	return hex.EncodeToString(bytes.NewBuffer(sum[:]).Bytes())
}

func IssuerKeyId(cert *x509.Certificate) string {
	return hex.EncodeToString(cert.AuthorityKeyId)
}

func SerialNumber(cert *x509.Certificate) string {
	return cert.SerialNumber.String()
}

func SerialNumberAsHexString(cert *x509.Certificate) string {
	return cert.SerialNumber.Text(16)
}

func SubjectName(cert *x509.Certificate) string {
	return cert.Subject.String()
}

func SubjectNameHash(cert *x509.Certificate) string {
	sum := sha1.Sum(cert.RawSubject)
	return hex.EncodeToString(bytes.NewBuffer(sum[:]).Bytes())
}

func SubjectKeyId(cert *x509.Certificate) string {
	return hex.EncodeToString(cert.SubjectKeyId)
}

func NotBefore(cert *x509.Certificate) string {
	return cert.NotBefore.String()
}

func NotAfter(cert *x509.Certificate) string {
	return cert.NotAfter.String()
}
