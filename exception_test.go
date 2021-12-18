// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"testing"
)

type TestExceptionEntry struct {
	entryCount  int
	entryIndex  int
	runtimeFunc ImageRuntimeFunctionEntry
	unwindInfo  UnwindInfo
}

func TestParseExceptionDirectory(t *testing.T) {

	tests := []struct {
		in  string
		out TestExceptionEntry
	}{
		{
			getAbsoluteFilePath("test/kernel32.dll"),
			TestExceptionEntry{
				entryCount: 1835,
				entryIndex: 0,
				runtimeFunc: ImageRuntimeFunctionEntry{
					BeginAddress:      0x1010,
					EndAddress:        0x1053,
					UnwindInfoAddress: 0x938b8,
				},
				unwindInfo: UnwindInfo{
					Version:       0x1,
					Flags:         0x0,
					SizeOfProlog:  0x7,
					CountOfCodes:  0x1,
					FrameRegister: 0x0,
					FrameOffset:   0x0,
					UnwindCodes: []UnwindCode{
						{
							CodeOffset:  0x07,
							UnwindOp:    0x2,
							OpInfo:      0x8,
							Operand:     "Size=72",
							FrameOffset: 0x0,
						},
					},
				},
			},
		},
		{
			// fake exception directory
			getAbsoluteFilePath("test/0585495341e0ffaae1734acb78708ff55cd3612d844672d37226ef63d12652d0"),
			TestExceptionEntry{
				entryCount: 3349,
				entryIndex: 0,
				runtimeFunc: ImageRuntimeFunctionEntry{
					BeginAddress:      0xf860617,
					EndAddress:        0x205fef60,
					UnwindInfoAddress: 0x2c0365b4,
				},
				unwindInfo: UnwindInfo{},
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
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryException]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			case false:
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryException]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseExceptionDirectory(va, size)
			if err != nil {
				t.Fatalf("parseExceptionDirectory(%s) failed, reason: %v", tt.in, err)
			}
			got := file.Exceptions
			if len(got) != tt.out.entryCount {
				t.Errorf("Exception entry count assertion failed, got %v, want %v", len(got), tt.out.entryCount)
			}

			runtimeFunc := file.Exceptions[tt.out.entryIndex].RuntimeFunction
			if runtimeFunc != tt.out.runtimeFunc {
				t.Errorf("RuntimeFunction assertion failed, got %v, want %v", len(got), tt.out.entryCount)
			}

			unwinInfo := file.Exceptions[tt.out.entryIndex].UnwinInfo
			if !reflect.DeepEqual(unwinInfo, tt.out.unwindInfo) {
				t.Errorf("UnwinInfo assertion failed, got %v, want %v", unwinInfo, tt.out.unwindInfo)
			}

		})
	}
}
