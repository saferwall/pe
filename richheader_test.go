// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"testing"
)

type TestRichHeader struct {
	richHeader   RichHeader
	compIDIndex  uint8
	prettyProdID string
	VSVersion    string
	checksum     uint32
}

func TestParseRichHeader(t *testing.T) {

	tests := []struct {
		in  string
		out TestRichHeader
	}{
		{getAbsoluteFilePath("test/kernel32.dll"),
			TestRichHeader{
				richHeader: RichHeader{
					XORKey: 2796214951,
					CompIDs: []CompID{
						{
							MinorCV:  27412,
							ProdID:   257,
							Count:    4,
							Unmasked: 16870164,
						},
						{
							MinorCV:  30729,
							ProdID:   147,
							Count:    193,
							Unmasked: 9664521,
						},
						{
							MinorCV:  0,
							ProdID:   1,
							Count:    1325,
							Unmasked: 65536,
						},
						{
							MinorCV:  27412,
							ProdID:   260,
							Count:    9,
							Unmasked: 17066772,
						},
						{
							MinorCV:  27412,
							ProdID:   259,
							Count:    3,
							Unmasked: 17001236,
						},
						{
							MinorCV:  27412,
							ProdID:   256,
							Count:    1,
							Unmasked: 16804628,
						},
						{
							MinorCV:  27412,
							ProdID:   269,
							Count:    209,
							Unmasked: 17656596,
						},
						{
							MinorCV:  27412,
							ProdID:   255,
							Count:    1,
							Unmasked: 16739092,
						},
						{
							MinorCV:  27412,
							ProdID:   258,
							Count:    1,
							Unmasked: 16935700,
						},
					},
					DansOffset: 128,
					Raw: []byte{
						0xe3, 0xbb, 0xc4, 0xf5, 0xa7, 0xda, 0xaa, 0xa6, 0xa7, 0xda, 0xaa, 0xa6, 0xa7, 0xda, 0xaa,
						0xa6, 0xb3, 0xb1, 0xab, 0xa7, 0xa3, 0xda, 0xaa, 0xa6, 0xae, 0xa2, 0x39, 0xa6, 0x66, 0xda,
						0xaa, 0xa6, 0xa7, 0xda, 0xab, 0xa6, 0x8a, 0xdf, 0xaa, 0xa6, 0xb3, 0xb1, 0xae, 0xa7, 0xae,
						0xda, 0xaa, 0xa6, 0xb3, 0xb1, 0xa9, 0xa7, 0xa4, 0xda, 0xaa, 0xa6, 0xb3, 0xb1, 0xaa, 0xa7,
						0xa6, 0xda, 0xaa, 0xa6, 0xb3, 0xb1, 0xa7, 0xa7, 0x76, 0xda, 0xaa, 0xa6, 0xb3, 0xb1, 0x55,
						0xa6, 0xa6, 0xda, 0xaa, 0xa6, 0xb3, 0xb1, 0xa8, 0xa7, 0xa6, 0xda, 0xaa, 0xa6, 0x52, 0x69,
						0x63, 0x68, 0xa7, 0xda, 0xaa, 0xa6},
				},
				compIDIndex:  3,
				prettyProdID: "Utc1900_C",
				VSVersion:    "Visual Studio 2015 14.00",
				checksum:     0xa6aadaa7,
			}},
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

			richHeader := file.RichHeader
			if !reflect.DeepEqual(richHeader, tt.out.richHeader) {
				t.Errorf("rich header test failed, got %v, want %v",
				richHeader, tt.out)
			}

			prodID := richHeader.CompIDs[tt.out.compIDIndex].ProdID
			prettyProdID := ProdIDtoStr(prodID)
			if prettyProdID != tt.out.prettyProdID {
				t.Errorf("rich header pretty prod ID failed, got %v, want %v",
					prettyProdID, tt.out.prettyProdID)
			}

			VSVersion := ProdIDtoVSversion(prodID)
			if VSVersion != tt.out.VSVersion {
				t.Errorf("rich header VS verion of prod ID failed, got %v, want %v",
					VSVersion, tt.out.VSVersion)
			}

			checksum := file.RichHeaderChecksum()
			if checksum != tt.out.checksum {
				t.Errorf("rich header checksum failed, got %v, want %v",
					checksum, tt.out.checksum)
			}

		})
	}
}

func TestRichHeaderHash(t *testing.T) {

	tests := []struct {
		in  string
		out string
	}{
		{getAbsoluteFilePath("test/kernel32.dll"),
			"4549320af6790d410f09ddc3bab86c86"},
		{getAbsoluteFilePath("test/WdBoot.sys"),
			"3cbccbf62a2a6a8066a5c9d294c90948"},
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

			got := file.RichHeaderHash()
			if string(got) != tt.out {
				t.Errorf("Authentihash(%s) got %v, want %v", tt.in, got, tt.out)
			}

		})
	}
}
