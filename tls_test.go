// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"testing"
)

func TestParseTLSDirectory(t *testing.T) {

	tests := []struct {
		in  string
		out TLSDirectory
	}{
		{
			getAbsoluteFilePath("test/liblzo2-2.dll"),
			TLSDirectory{
				Struct: ImageTLSDirectory64{
					StartAddressOfRawData: 0x6CBBB000,
					EndAddressOfRawData:   0x6CBBB060,
					AddressOfIndex:        0x6CBB75AC,
					AddressOfCallBacks:    0x6CBBA030,
				},
				Callbacks: []uint64{0x6cbae7e0, 0x6cbae7b0},
			},
		},
		{
			getAbsoluteFilePath("test/3a081c7fe475ec68ed155c76d30cfddc4d41f7a09169810682d1c75421e98eaa"),
			TLSDirectory{
				Struct: ImageTLSDirectory32{
					StartAddressOfRawData: 0x004157B8,
					EndAddressOfRawData:   0x004157B9,
					AddressOfIndex:        0x0042F8DC,
					AddressOfCallBacks:    0x0040E3AC,
					Characteristics:       0x00100000,
				},
				Callbacks: []uint32{0x40A5A0},
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
			switch file.Is64 {
			case true:
				oh64 := file.NtHeader.OptionalHeader.(ImageOptionalHeader64)
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryTLS]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			case false:
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryTLS]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseTLSDirectory(va, size)
			if err != nil {
				t.Fatalf("parseRelocDirectory(%s) failed, reason: %v", tt.in, err)
			}
			tls := file.TLS
			if !reflect.DeepEqual(tls, tt.out) {
				t.Fatalf("TLS directory assertion failed, got %v, want %v", tls.Struct,
					tt.out)
			}
		})
	}
}

func TestTLSDirectoryCharacteristics(t *testing.T) {

	tests := []struct {
		in  TLSDirectoryCharacteristicsType
		out string
	}{
		{

			TLSDirectoryCharacteristicsType(0x00100000),
			"Align 1-Byte",
		},
		{
			0xff,
			"?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.out, func(t *testing.T) {

			TLSDirectoryCharacteristics := tt.in.String()
			if TLSDirectoryCharacteristics != tt.out {
				t.Fatalf("TLS directory characteristics string assertion failed, got %v, want %v",
					TLSDirectoryCharacteristics, tt.out)
			}
		})
	}
}
