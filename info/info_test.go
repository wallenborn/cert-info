package info_test

import (
	"certinfo/info"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
)

const (
	novoCert string = `-----BEGIN CERTIFICATE-----
MIIFTDCCBDSgAwIBAgISA/phEzaZQhfdRxpoH1mbVOrQMA0GCSqGSIb3DQEBCwUA
MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
EwJSMzAeFw0yMzEwMDkwMzI3NDJaFw0yNDAxMDcwMzI3NDFaMCMxITAfBgNVBAMT
GGF1dG9kaXNjb3Zlci5ub3Zvc2VjLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBANuodNyaAqLwQxono6/xXeWdAJeHlUUU3RQzmmpRPfL1bchIbtMD
lT4hXVm8sxMCuoAe66dXHddFAQuV7N9sVqYsHJ5ac+HectGXjd2xfUpZC9fycaka
d5f5BtKTtFmAV47K2x0fKwDGY+dWF9fR50wvvLvCHVW2f97rPdzHn8ioK20HGP2L
/eBTiCcAVY3oR5xn438nv24tlud+W1OYmJv8bAHKByRXiNZ+uD7t/I8x4k9F3dyT
01/S1UNURYtvKSDo7KEFgnyEqW0tPwXo/KidhIJgznbyQZBGxqzmdyzy7o2dnO5v
FfROx0JgtK7Jwd/yxFXczrinttUbtZWfnpECAwEAAaOCAmkwggJlMA4GA1UdDwEB
/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/
BAIwADAdBgNVHQ4EFgQU4AltNru1Iy5QB37Esv1nfX+xfPYwHwYDVR0jBBgwFoAU
FC6zF7dYVsuuUAlA5h+vnYsUwsYwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzAB
hhVodHRwOi8vcjMuby5sZW5jci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5p
LmxlbmNyLm9yZy8wcAYDVR0RBGkwZ4IYYXV0b2Rpc2NvdmVyLm5vdm9zZWMuY29t
ghFsaW1lcy5ub3Zvc2VjLmNvbYILbm92b3NlYy5jb22CCm5vdm9zZWMuZGWCD3d3
dy5ub3Zvc2VjLmNvbYIOd3d3Lm5vdm9zZWMuZGUwEwYDVR0gBAwwCjAIBgZngQwB
AgEwggEGBgorBgEEAdZ5AgQCBIH3BIH0APIAdwDatr9rP7W2Ip+bwrtca+hwkXFs
u1GEhTS9pD0wSNf7qwAAAYsSsN3QAAAEAwBIMEYCIQCjK3aXp4MWpaK/AFIsaBd9
tqcl6xje6g+1lYANEbf7kAIhAIThsbdU34Ws+CgOyCUezivoIvNKtDDVLOyJA+fO
wc9jAHcA7s3QZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZsAAAGLErDdvAAA
BAMASDBGAiEAjM4gtLQyrnBrPFK+LRRI+9e/pj62PfAqOPz3xY3SSGcCIQDQ2S1h
Q5HNOBvQaNYIdaza/iHP6ZjmI8yO1VzDduvmyjANBgkqhkiG9w0BAQsFAAOCAQEA
D6yuaIUnWTAEtDwESe7nSPubnedy9pnBPXomkJL8jXR+O7iIjQwWX+vOl6r80Vdt
vZIjWqc1YL9zcDhKUFLGMNvp6d2NQIIql97cP4pHH5X7vbvnIumKKfuYuoePEpi0
BNA1Y1bu9y5dmRmru1I0H87vFbEdX7j4TMNC//9OW92P0VFr0bIIUaELxNjJ1O98
H9nGEzLPbQ+VLaSVTC6C7Ngni43CBZCMSVOF5FNlNCHeXNACb76X1tmhUokCF6tZ
WreTDblwu0Cw+NjH1OXBfJU5VAitO8pSj6rNzmqr9EMqIw6IeVbFkqceBN8vBshr
ZEPJH9+sNImbSLqFimP3Rw==
-----END CERTIFICATE-----`
)

func TestSubjectName(t *testing.T) {
	var cert *x509.Certificate = ReadCertificate(novoCert)
	if info.SubjectName(cert) != "CN=autodiscover.novosec.com" {
		t.Fail()
	}
}

func TestSubjectNameHash(t *testing.T) {
	var cert *x509.Certificate = ReadCertificate(novoCert)
	if info.SubjectNameHash(cert) != "6a65f265d1f7b66367918a39d4026f0b63096c59" {
		t.Fail()
	}
}

func TestSubjectKeyId(t *testing.T) {
	var cert *x509.Certificate = ReadCertificate(novoCert)
	if info.SubjectKeyId(cert) != "e0096d36bbb5232e50077ec4b2fd677d7fb17cf6" {
		t.Fail()
	}
}
func ReadCertificate(str string) *x509.Certificate {
	cc, _ := pem.Decode([]byte(str))
	cert, err := x509.ParseCertificate(cc.Bytes)
	if err != nil {
		fmt.Println("Could not parse certificate")
	}
	return cert
}
