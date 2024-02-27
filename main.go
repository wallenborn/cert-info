package main

import (
	"certinfo/info"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func main() {

	args := os.Args[1:]
	if len(args) != 1 {
		fmt.Println("Usage: certinfo <pemfile>")
		os.Exit(1)
	}

	filename := args[0]
	buf, err := os.ReadFile(filename)
	if err != nil {
		fmt.Println("Could not load certificate from file " + filename)
	}
	cc, _ := pem.Decode([]byte(buf))
	cert, err := x509.ParseCertificate(cc.Bytes)
	if err != nil {
		fmt.Println("Could not parse certificate")
	}

	fmt.Println("Subject Name:        " + info.SubjectName(cert))
	fmt.Println("Issuer Name:         " + info.IssuerName(cert))
	fmt.Println("Serial Number (dec): " + info.SerialNumber(cert))
	fmt.Println("Serial Number (hex): " + info.SerialNumberAsHexString(cert))
	fmt.Println("Not Before:          " + info.NotBefore(cert))
	fmt.Println("Not After:           " + info.NotAfter(cert))
	fmt.Println("Subject Name Hash:   " + info.SubjectNameHash(cert))
	fmt.Println("Subject Key Id:      " + info.SubjectKeyId(cert))
	fmt.Println("Issuer Name Hash:    " + info.IssuerNameHash(cert))
	fmt.Println("Issuer Key Id:       " + info.IssuerKeyId(cert))
}
