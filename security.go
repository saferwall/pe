// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/secDre4mer/pkcs7"
)

// The options for the WIN_CERTIFICATE Revision member include
// (but are not limited to) the following.
const (
	// WinCertRevision1_0 represents the WIN_CERT_REVISION_1_0 Version 1,
	// legacy version of the Win_Certificate structure.
	// It is supported only for purposes of verifying legacy Authenticode
	// signatures
	WinCertRevision1_0 = 0x0100

	// WinCertRevision2_0 represents the WIN_CERT_REVISION_2_0. Version 2
	// is the current version of the Win_Certificate structure.
	WinCertRevision2_0 = 0x0200
)

// The options for the WIN_CERTIFICATE CertificateType member include
// (but are not limited to) the items in the following table. Note that some
// values are not currently supported.
const (
	// Certificate contains an X.509 Certificate (Not Supported)
	WinCertTypeX509 = 0x0001

	// Certificate contains a PKCS#7 SignedData structure.
	WinCertTypePKCSSignedData = 0x0002

	// Reserved.
	WinCertTypeReserved1 = 0x0003

	// Terminal Server Protocol Stack Certificate signing (Not Supported).
	WinCertTypeTSStackSigned = 0x0004
)

var (
	// ErrSecurityDataDirInvalidCertHeader is reported when the certificate
	// header in the security directory is invalid.
	ErrSecurityDataDirInvalid = errors.New(
		`invalid certificate header in security directory`)
)

type CertificateSection struct {
	Header WinCertificate `json:"header"`
	Raw    []byte         `json:"-"`

	Certificates []Certificate
}

// Certificate directory.
type Certificate struct {
	Content          pkcs7.PKCS7         `json:"-"`
	SignatureContent AuthenticodeContent `json:"-"`
	SignatureValid   bool                `json:"signature_valid"`
	Info             CertInfo            `json:"info"`
	Verified         bool                `json:"verified"`
}

// WinCertificate encapsulates a signature used in verifying executable files.
type WinCertificate struct {
	// Specifies the length, in bytes, of the signature.
	Length uint32 `json:"length"`

	// Specifies the certificate revision.
	Revision uint16 `json:"revision"`

	// Specifies the type of certificate.
	CertificateType uint16 `json:"certificate_type"`
}

// CertInfo wraps the important fields of the pkcs7 structure.
// This is what we what keep in JSON marshalling.
type CertInfo struct {
	// The certificate authority (CA) that charges customers to issue
	// certificates for them.
	Issuer string `json:"issuer"`

	// The subject of the certificate is the entity its public key is associated
	// with (i.e. the "owner" of the certificate).
	Subject string `json:"subject"`

	// The certificate won't be valid before this timestamp.
	NotBefore time.Time `json:"not_before"`

	// The certificate won't be valid after this timestamp.
	NotAfter time.Time `json:"not_after"`

	// The serial number MUST be a positive integer assigned by the CA to each
	// certificate. It MUST be unique for each certificate issued by a given CA
	// (i.e., the issuer name and serial number identify a unique certificate).
	// CAs MUST force the serialNumber to be a non-negative integer.
	// For convenience, we convert the big int to string.
	SerialNumber string `json:"serial_number"`

	// The identifier for the cryptographic algorithm used by the CA to sign
	// this certificate.
	SignatureAlgorithm x509.SignatureAlgorithm `json:"signature_algorithm"`

	// The Public Key Algorithm refers to the public key inside the certificate.
	// This certificate is used together with the matching private key to prove
	// the identity of the peer.
	PublicKeyAlgorithm x509.PublicKeyAlgorithm `json:"public_key_algorithm"`
}

type RelRange struct {
	Start  uint32
	Length uint32
}

type byStart []RelRange

func (s byStart) Len() int      { return len(s) }
func (s byStart) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s byStart) Less(i, j int) bool {
	return s[i].Start < s[j].Start
}

type Range struct {
	Start uint32
	End   uint32
}

func (pe *File) parseLocations() (map[string]*RelRange, error) {
	location := make(map[string]*RelRange, 3)

	fileHdrSize := uint32(binary.Size(pe.NtHeader.FileHeader))
	optionalHeaderOffset := pe.DOSHeader.AddressOfNewEXEHeader + 4 + fileHdrSize

	var (
		oh32 ImageOptionalHeader32
		oh64 ImageOptionalHeader64

		optionalHeaderSize uint32
	)

	switch pe.Is64 {
	case true:
		oh64 = pe.NtHeader.OptionalHeader.(ImageOptionalHeader64)
		optionalHeaderSize = oh64.SizeOfHeaders
	case false:
		oh32 = pe.NtHeader.OptionalHeader.(ImageOptionalHeader32)
		optionalHeaderSize = oh32.SizeOfHeaders
	}

	if optionalHeaderSize > pe.size-optionalHeaderOffset {
		msgF := "the optional header exceeds the file length (%d + %d > %d)"
		return nil, fmt.Errorf(msgF, optionalHeaderSize, optionalHeaderOffset, pe.size)
	}

	if optionalHeaderSize < 68 {
		msgF := "the optional header size is %d < 68, which is insufficient for authenticode"
		return nil, fmt.Errorf(msgF, optionalHeaderSize)
	}

	// The location of the checksum
	location["checksum"] = &RelRange{optionalHeaderOffset + 64, 4}

	var rvaBase, certBase, numberOfRvaAndSizes uint32
	switch pe.Is64 {
	case true:
		rvaBase = optionalHeaderOffset + 108
		certBase = optionalHeaderOffset + 144
		numberOfRvaAndSizes = oh64.NumberOfRvaAndSizes
	case false:
		rvaBase = optionalHeaderOffset + 92
		certBase = optionalHeaderOffset + 128
		numberOfRvaAndSizes = oh32.NumberOfRvaAndSizes
	}

	if optionalHeaderOffset+optionalHeaderSize < rvaBase+4 {
		pe.logger.Debug("The PE Optional Header size can not accommodate for the NumberOfRvaAndSizes field")
		return location, nil
	}

	if numberOfRvaAndSizes < uint32(5) {
		pe.logger.Debugf("The PE Optional Header does not have a Certificate Table entry in its "+
			"Data Directory; NumberOfRvaAndSizes = %d", numberOfRvaAndSizes)
		return location, nil
	}

	if optionalHeaderOffset+optionalHeaderSize < certBase+8 {
		pe.logger.Debug("The PE Optional Header size can not accommodate for a Certificate Table" +
			"entry in its Data Directory")
		return location, nil
	}

	// The location of the entry of the Certificate Table in the Data Directory
	location["datadir_certtable"] = &RelRange{certBase, 8}

	var address, size uint32
	switch pe.Is64 {
	case true:
		dirEntry := oh64.DataDirectory[ImageDirectoryEntryCertificate]
		address = dirEntry.VirtualAddress
		size = dirEntry.Size
	case false:
		dirEntry := oh32.DataDirectory[ImageDirectoryEntryCertificate]
		address = dirEntry.VirtualAddress
		size = dirEntry.Size
	}

	if size == 0 {
		pe.logger.Debug("The Certificate Table is empty")
		return location, nil
	}

	if int64(address) < int64(optionalHeaderSize)+int64(optionalHeaderOffset) ||
		int64(address)+int64(size) > int64(pe.size) {
		pe.logger.Debugf("The location of the Certificate Table in the binary makes no sense and "+
			"is either beyond the boundaries of the file, or in the middle of the PE header; "+
			"VirtualAddress: %x, Size: %x", address, size)
		return location, nil
	}

	// The location of the Certificate Table
	location["certtable"] = &RelRange{address, size}
	return location, nil
}

// Authentihash generates the SHA256 pe image file hash.
// The relevant sections to exclude during hashing are:
//   - The location of the checksum
//   - The location of the entry of the Certificate Table in the Data Directory
//   - The location of the Certificate Table.
func (pe *File) Authentihash() []byte {
	results := pe.AuthentihashExt(crypto.SHA256.New())
	if len(results) > 0 {
		return results[0]
	}
	return nil
}

// AuthentihashExt generates pe image file hashes using the given hashers.
// The relevant sections to exclude during hashing are:
//   - The location of the checksum
//   - The location of the entry of the Certificate Table in the Data Directory
//   - The location of the Certificate Table.
func (pe *File) AuthentihashExt(hashers ...hash.Hash) [][]byte {

	locationMap, err := pe.parseLocations()
	if err != nil {
		return nil
	}

	locationSlice := make([]RelRange, 0, len(locationMap))
	for k, v := range locationMap {
		if stringInSlice(k, []string{"checksum", "datadir_certtable", "certtable"}) {
			locationSlice = append(locationSlice, *v)
		}
	}
	sort.Sort(byStart(locationSlice))

	ranges := make([]*Range, 0, len(locationSlice))
	start := uint32(0)
	for _, r := range locationSlice {
		ranges = append(ranges, &Range{Start: start, End: r.Start})
		start = r.Start + r.Length
	}
	ranges = append(ranges, &Range{Start: start, End: pe.size})

	var rd io.ReaderAt
	if pe.f != nil {
		rd = pe.f
	} else {
		rd = bytes.NewReader(pe.data)
	}

	for _, v := range ranges {
		for _, hasher := range hashers {
			sr := io.NewSectionReader(rd, int64(v.Start), int64(v.End)-int64(v.Start))
			io.Copy(hasher, sr)
			sr.Seek(0, io.SeekStart)
		}
	}

	var ret [][]byte
	for _, hasher := range hashers {
		ret = append(ret, hasher.Sum(nil))
	}

	return ret
}

// The security directory contains the authenticode signature, which is a digital
// signature format that is used, among other purposes, to determine the origin
// and integrity of software binaries. Authenticode is based on the Public-Key
// Cryptography Standards (PKCS) #7 standard and uses X.509 v3 certificates to
// bind an Authenticode-signed file to the identity of a software publisher.
// This data are not loaded into memory as part of the image file.
func (pe *File) parseSecurityDirectory(rva, size uint32) error {
	var certHeader WinCertificate
	certSize := uint32(binary.Size(certHeader))
	signatureContent := AuthenticodeContent{}

	// The virtual address value from the Certificate Table entry in the
	// Optional Header Data Directory is a file offset to the first attribute
	// certificate entry.
	fileOffset := rva

	err := pe.structUnpack(&certHeader, fileOffset, certSize)
	if err != nil {
		return ErrOutsideBoundary
	}

	if certHeader.Length > size {
		return ErrOutsideBoundary
	}

	if fileOffset+certHeader.Length > pe.size {
		return ErrOutsideBoundary
	}

	if certHeader.Length == 0 {
		return ErrSecurityDataDirInvalid
	}

	pe.HasCertificate = true
	pe.Certificates.Header = certHeader
	pe.Certificates.Raw = pe.data[fileOffset+certSize : fileOffset+certHeader.Length]

	certContent := pe.Certificates.Raw
	for {
		pkcs, err := pkcs7.Parse(certContent)
		if err != nil {
			return err
		}
		// The pkcs7.PKCS7 structure contains many fields that we are not
		// interested to, so create another structure, similar to _CERT_INFO
		// structure which contains only the important information.
		var signerCertificate = pkcs.GetOnlySigner()
		if signerCertificate == nil {
			return errors.New("could not find signer certificate")
		}

		var certInfo CertInfo

		certInfo.SerialNumber = hex.EncodeToString(signerCertificate.SerialNumber.Bytes())
		certInfo.PublicKeyAlgorithm = signerCertificate.PublicKeyAlgorithm

		certInfo.NotAfter = signerCertificate.NotAfter
		certInfo.NotBefore = signerCertificate.NotBefore

		// Issuer infos
		certInfo.Issuer = formatPkixName(signerCertificate.Issuer)

		// Subject infos
		certInfo.Subject = formatPkixName(signerCertificate.Subject)

		// Let's mark the file as signed, then we verify if the signature is valid.
		pe.IsSigned = true

		var certValid bool
		// Let's load the system root certs.
		if !pe.opts.DisableCertValidation {
			var certPool *x509.CertPool
			if runtime.GOOS == "windows" {
				certPool, err = loadSystemRoots()
			} else {
				certPool, err = x509.SystemCertPool()
			}

			// Verify the signature. This will also verify the chain of trust of the
			// the end-entity signer cert to one of the root in the trust store.
			if err != nil {
				pe.logger.Errorf("failed to loadSystemRoots: %v", err)
			} else {
				err = pkcs.VerifyWithChain(certPool)
				if err == nil {
					certValid = true
				} else {
					certValid = false
				}
			}
		}

		var signatureValid bool
		signatureContent, err = parseAuthenticodeContent(pkcs.Content)
		if err != nil {
			pe.logger.Errorf("could not parse authenticode content: %v", err)
			signatureValid = false
		} else if !pe.opts.DisableSignatureValidation {
			authentihash := pe.AuthentihashExt(signatureContent.HashFunction.New())[0]
			signatureValid = bytes.Equal(authentihash, signatureContent.HashResult)
		}

		certInfo.SignatureAlgorithm = signatureContent.Algorithm

		pe.Certificates.Certificates = append(pe.Certificates.Certificates, Certificate{
			Content:          *pkcs,
			SignatureContent: signatureContent,
			SignatureValid:   signatureValid,
			Info:             certInfo,
			Verified:         certValid,
		})

		// Subsequent certificates are an (unsigned) attribute of the PKCS#7
		var newCert asn1.RawValue
		nestedSignatureOid := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 4, 1}
		err = pkcs.UnmarshalUnsignedAttribute(nestedSignatureOid, &newCert)
		if err != nil {
			var attributeNotFound pkcs7.AttributeNotFoundError
			if errors.As(err, &attributeNotFound) {
				break // No further nested certificates
			}
			return err
		}
		certContent = newCert.FullBytes
	}

	return nil
}

// loadSystemsRoots manually downloads all the trusted root certificates
// in Windows by spawning certutil then adding root certs individually
// to the cert pool. Initially, when running in windows, go SystemCertPool()
// used to enumerate all the certificate in the Windows store using
// (CertEnumCertificatesInStore). Unfortunately, Windows does not ship
// with all of its root certificates installed. Instead, it downloads them
// on-demand. As a consequence, this behavior leads to a non-deterministic
// results. Go team then disabled the loading Windows root certs.
func loadSystemRoots() (*x509.CertPool, error) {

	needSync := true
	roots := x509.NewCertPool()

	// Create a temporary dir in the OS temp folder
	// if it does not exists.
	dir := filepath.Join(os.TempDir(), "certs")
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		if err = os.Mkdir(dir, 0755); err != nil {
			return roots, err
		}
	} else {
		now := time.Now()
		modTime := info.ModTime()
		diff := now.Sub(modTime).Hours()
		if diff < 24 {
			needSync = false
		}
	}

	// Use certutil to download all the root certs.
	if needSync {
		cmd := exec.Command("certutil", "-syncWithWU", dir)
		hideWindow(cmd)
		err := cmd.Run()
		if err != nil {
			return roots, err
		}
		if cmd.ProcessState.ExitCode() != 0 {
			return roots, err
		}
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		return roots, err
	}

	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".crt") {
			continue
		}
		certPath := filepath.Join(dir, f.Name())
		certData, err := os.ReadFile(certPath)
		if err != nil {
			return roots, err
		}

		if crt, err := x509.ParseCertificate(certData); err == nil {
			roots.AddCert(crt)
		}
	}

	return roots, nil
}

type SpcIndirectDataContent struct {
	Data          SpcAttributeTypeAndOptionalValue
	MessageDigest DigestInfo
}

type SpcAttributeTypeAndOptionalValue struct {
	Type  asn1.ObjectIdentifier
	Value SpcPeImageData `asn1:"optional"`
}

type SpcPeImageData struct {
	Flags asn1.BitString
	File  asn1.RawValue
}

type DigestInfo struct {
	DigestAlgorithm pkix.AlgorithmIdentifier
	Digest          []byte
}

// Translation of algorithm identifier to hash algorithm, copied from pkcs7.getHashForOID
func parseHashAlgorithm(identifier pkix.AlgorithmIdentifier) (crypto.Hash, x509.SignatureAlgorithm, error) {
	oid := identifier.Algorithm
	switch {
	case oid.Equal(pkcs7.OIDDigestAlgorithmSHA1), oid.Equal(pkcs7.OIDEncryptionAlgorithmRSA):
		return crypto.SHA1, x509.SHA1WithRSA, nil
	case oid.Equal(pkcs7.OIDDigestAlgorithmECDSASHA1):
		return crypto.SHA1, x509.ECDSAWithSHA1, nil
	case oid.Equal(pkcs7.OIDDigestAlgorithmDSA), oid.Equal(pkcs7.OIDDigestAlgorithmDSASHA1):
		return crypto.SHA1, x509.DSAWithSHA1, nil
	case oid.Equal(pkcs7.OIDDigestAlgorithmSHA256):
		return crypto.SHA256, x509.SHA256WithRSA, nil
	case oid.Equal(pkcs7.OIDDigestAlgorithmECDSASHA256):
		return crypto.SHA256, x509.ECDSAWithSHA256, nil
	case oid.Equal(pkcs7.OIDDigestAlgorithmSHA384):
		return crypto.SHA384, x509.SHA256WithRSA, nil
	case oid.Equal(pkcs7.OIDDigestAlgorithmECDSASHA384):
		return crypto.SHA384, x509.ECDSAWithSHA384, nil
	case oid.Equal(pkcs7.OIDDigestAlgorithmSHA512):
		return crypto.SHA512, x509.ECDSAWithSHA512, nil
	case oid.Equal(pkcs7.OIDDigestAlgorithmECDSASHA512):
		return crypto.SHA512, x509.ECDSAWithSHA512, nil
	}
	return 0, 0, pkcs7.ErrUnsupportedAlgorithm
}

// AuthenticodeContent provides a simplified view on SpcIndirectDataContent, which specifies the ASN.1 encoded values of
// the authenticode signature content.
type AuthenticodeContent struct {
	Algorithm    x509.SignatureAlgorithm
	HashFunction crypto.Hash
	HashResult   []byte
}

func parseAuthenticodeContent(content []byte) (AuthenticodeContent, error) {
	var authenticodeContent SpcIndirectDataContent
	content, err := asn1.Unmarshal(content, &authenticodeContent.Data)
	if err != nil {
		return AuthenticodeContent{}, err
	}
	_, err = asn1.Unmarshal(content, &authenticodeContent.MessageDigest)
	if err != nil {
		return AuthenticodeContent{}, err
	}
	hashFunction, algorithmID, err := parseHashAlgorithm(authenticodeContent.MessageDigest.DigestAlgorithm)
	if err != nil {
		return AuthenticodeContent{}, err
	}
	return AuthenticodeContent{
		Algorithm:    algorithmID,
		HashFunction: hashFunction,
		HashResult:   authenticodeContent.MessageDigest.Digest,
	}, nil
}

func formatPkixName(name pkix.Name) string {
	var formattedName string
	if len(name.Country) > 0 {
		formattedName = name.Country[0]
	}

	if len(name.Province) > 0 {
		formattedName += ", " + name.Province[0]
	}

	if len(name.Locality) > 0 {
		formattedName += ", " + name.Locality[0]
	}

	if len(name.Organization) > 0 {
		formattedName += ", " + name.Organization[0]
	}

	formattedName += ", " + name.CommonName

	return formattedName
}
