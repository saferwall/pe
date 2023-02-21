// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"testing"
)

func TestLoadConfigDirectory(t *testing.T) {

	tests := []struct {
		in  string
		out interface{}
	}{
		{
			in: getAbsoluteFilePath("test/00da1a2a9d9ebf447508bf6550f05f466f8eabb4ed6c4f2a524c0769b2d75bc1"),
			out: ImageLoadConfigDirectory32v3{
				Size:                        92,
				SecurityCookie:              4445800,
				SEHandlerTable:              4430960,
				SEHandlerCount:              37,
				GuardCFCheckFunctionPointer: 4399712,
				GuardCFFunctionTable:        4399828,
				GuardCFFunctionCount:        144,
				GuardFlags:                  268514560,
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
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			} else {
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryLoadConfig]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseLoadConfigDirectory(va, size)
			if err != nil {
				t.Fatalf("parseLoadConfigDirectory(%s) failed, reason: %v",
					tt.in, err)
			}

			imgLoadCfgDirectory := file.LoadConfig.Struct
			if imgLoadCfgDirectory != tt.out {
				t.Fatalf("debug entry assertion failed, got %v, want %v",
					imgLoadCfgDirectory, tt.out)
			}

		})
	}
}
