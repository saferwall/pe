// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"testing"
)

type TestRsrcDir struct {
	ImgRsrcDir ImageResourceDirectory
}

func TestParseResourceDirectory(t *testing.T) {

	tests := []struct {
		in  string
		out TestRsrcDir
	}{
		{
			getAbsoluteFilePath("test/putty.exe"),
			TestRsrcDir{
				ImgRsrcDir: ImageResourceDirectory{
					Characteristics:      0x0,
					TimeDateStamp:        0x0,
					MajorVersion:         0x0,
					MinorVersion:         0x0,
					NumberOfNamedEntries: 0x0,
					NumberOfIDEntries:    0x6,
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

			err = file.Parse()
			if err != nil {
				t.Fatalf("Parse(%s) failed, reason: %v", tt.in, err)
			}

			var va, size uint32
			if file.Is64 {
				oh64 := file.NtHeader.OptionalHeader.(ImageOptionalHeader64)
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryResource]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryResource]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseResourceDirectory(va, size)
			if err != nil {
				t.Fatalf("parseResourceDirectory(%s) failed, reason: %v", tt.in, err)
			}

			rsrc := file.Resources
			if rsrc.Struct != tt.out.ImgRsrcDir {
				t.Fatalf("resource directory assertion failed, got %v, want %v",
					rsrc.Struct, tt.out.ImgRsrcDir)

			}

		})
	}
}
