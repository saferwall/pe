// Copyright 2022 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"testing"
)

type TestDOSHeader struct {
	imageDOSHeader ImageDOSHeader
}

func TestParseDOSHeader(t *testing.T) {

	tests := []struct {
		in  string
		out TestDOSHeader
	}{
		{
			getAbsoluteFilePath("test/putty.exe"),
			TestDOSHeader{
				imageDOSHeader: ImageDOSHeader{
					Magic:                    0x5a4d,
					BytesOnLastPageOfFile:    0x78,
					PagesInFile:              0x1,
					Relocations:              0x0,
					SizeOfHeader:             0x4,
					MinExtraParagraphsNeeded: 0x0,
					MaxExtraParagraphsNeeded: 0x0,
					InitialSS:                0x0,
					InitialSP:                0x0,
					Checksum:                 0x0,
					InitialIP:                0x0,
					InitialCS:                0x0,
					AddressOfRelocationTable: 0x40,
					OverlayNumber:            0x0,
					ReservedWords1:           [4]uint16{},
					OEMIdentifier:            0x0,
					OEMInformation:           0x0,
					ReservedWords2:           [10]uint16{},
					AddressOfNewEXEHeader:    0x78,
				},
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

			err = file.ParseDOSHeader()
			if err != nil {
				t.Fatalf("Parse(%s) failed, reason: %v", tt.in, err)
			}

			got := file.DOSHeader
			if got != tt.out.imageDOSHeader {
				t.Errorf("parse DOS header assertion failed, got %v, want %v", got,
					tt.out.imageDOSHeader)
			}

		})
	}
}
