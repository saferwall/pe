// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"crypto/x509"
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type TestSecurityEntry struct {
	Header       WinCertificate
	Certificates []Certificate
	err          error
}

func TestParseSecurityDirectory(t *testing.T) {

	tests := []struct {
		in  string
		out TestSecurityEntry
	}{
		{
			getAbsoluteFilePath("test/putty.exe"),
			TestSecurityEntry{
				Header: WinCertificate{
					Length:          0x3D90,
					Revision:        0x200,
					CertificateType: 0x2,
				},
				Certificates: []Certificate{
					{
						Info: CertInfo{
							Issuer:             "GB, Greater Manchester, Salford, COMODO CA Limited, COMODO RSA Code Signing CA",
							Subject:            "GB, Cambridgeshire, Cambridge, Simon Tatham, Simon Tatham",
							NotBefore:          time.Date(2018, time.November, 13, 00, 00, 0, 0, time.UTC),
							NotAfter:           time.Date(2021, time.November, 8, 23, 59, 59, 0, time.UTC),
							SerialNumber:       "7c1118cbbadc95da3752c46e47a27438",
							PublicKeyAlgorithm: x509.RSA,
							SignatureAlgorithm: x509.SHA1WithRSA,
						},
						Verified:       true,
						SignatureValid: true,
					},
					{
						Info: CertInfo{
							Issuer:             "GB, Greater Manchester, Salford, COMODO CA Limited, COMODO RSA Code Signing CA",
							Subject:            "GB, Cambridgeshire, Cambridge, Simon Tatham, Simon Tatham",
							NotBefore:          time.Date(2018, time.November, 13, 00, 00, 0, 0, time.UTC),
							NotAfter:           time.Date(2021, time.November, 8, 23, 59, 59, 0, time.UTC),
							SerialNumber:       "7c1118cbbadc95da3752c46e47a27438",
							PublicKeyAlgorithm: x509.RSA,
							SignatureAlgorithm: x509.SHA256WithRSA,
						},
						Verified:       true,
						SignatureValid: true,
					},
				},
				err: nil,
			},
		},
		{
			getAbsoluteFilePath("test/putty_modified.exe"),
			TestSecurityEntry{
				Header: WinCertificate{
					Length:          0x3D90,
					Revision:        0x200,
					CertificateType: 0x2,
				},
				Certificates: []Certificate{
					{
						Info: CertInfo{
							Issuer:             "GB, Greater Manchester, Salford, COMODO CA Limited, COMODO RSA Code Signing CA",
							Subject:            "GB, Cambridgeshire, Cambridge, Simon Tatham, Simon Tatham",
							NotBefore:          time.Date(2018, time.November, 13, 00, 00, 0, 0, time.UTC),
							NotAfter:           time.Date(2021, time.November, 8, 23, 59, 59, 0, time.UTC),
							SerialNumber:       "7c1118cbbadc95da3752c46e47a27438",
							PublicKeyAlgorithm: x509.RSA,
							SignatureAlgorithm: x509.SHA1WithRSA,
						},
						Verified:       true,
						SignatureValid: false,
					},
					{
						Info: CertInfo{
							Issuer:             "GB, Greater Manchester, Salford, COMODO CA Limited, COMODO RSA Code Signing CA",
							Subject:            "GB, Cambridgeshire, Cambridge, Simon Tatham, Simon Tatham",
							NotBefore:          time.Date(2018, time.November, 13, 00, 00, 0, 0, time.UTC),
							NotAfter:           time.Date(2021, time.November, 8, 23, 59, 59, 0, time.UTC),
							SerialNumber:       "7c1118cbbadc95da3752c46e47a27438",
							PublicKeyAlgorithm: x509.RSA,
							SignatureAlgorithm: x509.SHA256WithRSA,
						},
						Verified:       true,
						SignatureValid: false,
					},
				},
				err: nil,
			},
		},
		{
			getAbsoluteFilePath("test/579fd8a0385482fb4c789561a30b09f25671e86422f40ef5cca2036b28f99648"),
			TestSecurityEntry{
				Header: WinCertificate{
					Length:          0x3488,
					Revision:        0x200,
					CertificateType: 0x2,
				},
				Certificates: []Certificate{
					{
						Info: CertInfo{
							Issuer:             "US, VeriSign, Inc., VeriSign Class 3 Code Signing 2010 CA",
							Subject:            "US, California, Mountain View, Symantec Corporation, Symantec Corporation",
							NotBefore:          time.Date(2016, time.December, 16, 00, 00, 0, 0, time.UTC),
							NotAfter:           time.Date(2017, time.December, 17, 23, 59, 59, 0, time.UTC),
							SerialNumber:       "0ebfea68d677b3e26cab41c33f3e69de",
							PublicKeyAlgorithm: x509.RSA,
							SignatureAlgorithm: x509.SHA1WithRSA,
						},
						Verified:       false,
						SignatureValid: false,
					},
					{
						Info: CertInfo{
							Issuer:             "US, Symantec Corporation, Symantec Class 3 SHA256 Code Signing CA - G2",
							Subject:            "US, California, Mountain View, Symantec Corporation, Symantec Corporation",
							NotBefore:          time.Date(2017, time.March, 15, 00, 00, 0, 0, time.UTC),
							NotAfter:           time.Date(2018, time.April, 13, 23, 59, 59, 0, time.UTC),
							SerialNumber:       "2e6be6bd11a8676e6c57909e9b0d5f57",
							PublicKeyAlgorithm: x509.RSA,
							SignatureAlgorithm: x509.SHA256WithRSA,
						},
						Verified:       false,
						SignatureValid: false,
					},
				},
				err: nil,
			},
		},
		{
			getAbsoluteFilePath("test/00121dae38f26a33da2990987db58738c5a5966930126a42f606a3b40e014624"),
			TestSecurityEntry{
				err: ErrSecurityDataDirInvalid,
			},
		},
	}

	for _, tt := range tests {
		t.Run(filepath.Base(tt.in), func(t *testing.T) {
			ops := Options{Fast: true}
			file, err := New(tt.in, &ops)
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in, err)
			}

			err = file.Parse()
			if err != nil {
				t.Fatalf("Parse(%s) failed, reason: %v", tt.in, err)
			}

			var va, size uint32
			if file.Is64 {
				oh64 := file.NtHeader.OptionalHeader.(ImageOptionalHeader64)
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryCertificate]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryCertificate]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseSecurityDirectory(va, size)
			if err != tt.out.err {
				t.Fatalf("parseSecurityDirectory(%s) failed, reason: %v", tt.in, err)
			}

			got := file.Certificates
			if tt.out.err == nil {
				if !reflect.DeepEqual(got.Header, tt.out.Header) {
					t.Fatalf("certificate header assertion failed, got %v, want %v", got.Header, tt.out.Header)
				}
			}
			if len(got.Certificates) != len(tt.out.Certificates) {
				t.Fatalf("certificate count assertion failed, got %d, want %d", len(got.Certificates), len(tt.out.Certificates))
			}
			for i, cert := range got.Certificates {
				expected := tt.out.Certificates[i]
				if !reflect.DeepEqual(cert.Info, expected.Info) {
					t.Fatalf("certificate info %d assertion failed, got %v, want %v", i, cert.Info, expected.Info)
				}
				if expected.SignatureValid != cert.SignatureValid {
					t.Fatalf("signature verification %d failed, cert %v, want %v", i, cert.SignatureValid, expected.SignatureValid)
				}
				if expected.Verified != cert.Verified {
					t.Fatalf("certificate verification %d failed, cert %v, want %v", i, cert.Verified, expected.Verified)
				}

			}
		})
	}
}

func TestAuthentihash(t *testing.T) {

	tests := []struct {
		in  string
		out string
	}{
		{getAbsoluteFilePath("test/putty.exe"),
			"8be7d65593b0fff2e8b29004640261b8a0d4fcc651a14cd0b8b702b7928f8ee0"},
		{getAbsoluteFilePath("test/mscorlib.dll"),
			"a52bd7784efbf206dbda2db058f3928deaf15f6fedf2773affae56023e2f0edb"},
		{getAbsoluteFilePath("test/liblzo2-2.dll"),
			"ae603480b92c7ea3feca164010d2594f9a5282f8b732ecaa0aca29f3225835f6"},
		{getAbsoluteFilePath("test/kernel32.dll"),
			"595e4eb556587a1363ff297df9f354a377963ecac0bed19230992b9601426aae"},
		{getAbsoluteFilePath("test/mfc40u.dll"),
			"5c8acdf9b2c7854c6b8e22e973d2fbae9c68fc22513d24c68c8e8010b1663e67"},
		{getAbsoluteFilePath("test/000057fd78f66e64e15f5070364c824a8923b6216bd8bcf6368857fb9674c483"),
			""},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			file, err := New(tt.in, &Options{})
			if err != nil {
				t.Fatalf("New(%s) failed, reason: %v", tt.in, err)
			}
			err = file.Parse()
			if err != nil {
				t.Fatalf("Parse(%s) failed, reason: %v", tt.in, err)
			}

			hash := file.Authentihash()
			got := fmt.Sprintf("%x", hash)
			if string(got) != tt.out {
				t.Errorf("Authentihash(%s) got %v, want %v", tt.in, got, tt.out)
			}
		})
	}
}
