// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"fmt"
	"reflect"
	"testing"
	"time"
)

type TestSecurityEntry struct {
	Header   WinCertificate
	Info     CertInfo
	Verified bool
	err      error
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
				Info: CertInfo{
					Issuer:    "GB, Greater Manchester, Salford, COMODO RSA Code Signing CA",
					Subject:   "GB, Cambridgeshire, Cambridge, Simon Tatham, Simon Tatham",
					NotBefore: time.Date(2018, time.November, 13, 00, 00, 0, 0, time.UTC),
					NotAfter:  time.Date(2021, time.November, 8, 23, 59, 59, 0, time.UTC),
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
		t.Run(tt.in, func(t *testing.T) {
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
				if !reflect.DeepEqual(got.Info, tt.out.Info) {
					t.Fatalf("certificate info assertion failed, got %v, want %v", got.Info, tt.out.Info)
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
