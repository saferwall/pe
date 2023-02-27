// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"testing"
)

func TestLoadConfigDirectory(t *testing.T) {

	tests := []struct {
		in  string
		out interface{}
	}{
		{
			in: getAbsoluteFilePath("test/pspluginwkr.dll"),
			out: ImageLoadConfigDirectory32{
				Size:           0x48,
				SecurityCookie: 0x45e44220,
				SEHandlerTable: 0x45e382e0,
				SEHandlerCount: 0x1,
			},
		},
		{
			in: getAbsoluteFilePath("test/00da1a2a9d9ebf447508bf6550f05f466f8eabb4ed6c4f2a524c0769b2d75bc1"),
			out: ImageLoadConfigDirectory32{
				Size:                        0x5c,
				SecurityCookie:              0x43D668,
				SEHandlerTable:              0x439C70,
				SEHandlerCount:              0x25,
				GuardCFCheckFunctionPointer: 0x432260,
				GuardCFFunctionTable:        0x4322D4,
				GuardCFFunctionCount:        0x90,
				GuardFlags:                  0x10013500,
			},
		},
		{
			in: getAbsoluteFilePath("test/3a081c7fe475ec68ed155c76d30cfddc4d41f7a09169810682d1c75421e98eaa"),
			out: ImageLoadConfigDirectory32{
				Size:                        0xa0,
				SecurityCookie:              0x417008,
				SEHandlerTable:              0x415410,
				SEHandlerCount:              0x2,
				GuardCFCheckFunctionPointer: 0x40e384,
				GuardFlags:                  0x100,
			},
		},

		{
			in: getAbsoluteFilePath("test/IEAdvpack.dll"),
			out: ImageLoadConfigDirectory32{
				Size:                           0xa4,
				SecurityCookie:                 0x6501b074,
				SEHandlerTable:                 0x650046d0,
				SEHandlerCount:                 0x1,
				GuardCFCheckFunctionPointer:    0x6502937c,
				GuardCFFunctionTable:           0x650010f0,
				GuardCFFunctionCount:           0x55,
				GuardFlags:                     0x10017500,
				GuardAddressTakenIatEntryTable: 0x6500129c,
				GuardAddressTakenIatEntryCount: 0x1,
				GuardLongJumpTargetTable:       0x650012a4,
				GuardLongJumpTargetCount:       0x2,
			},
		},
		{
			in: getAbsoluteFilePath("test/KernelBase.dll"),
			out: ImageLoadConfigDirectory32{
				Size:                           0xb8,
				DependentLoadFlags:             0x800,
				SecurityCookie:                 0x101f3b50,
				SEHandlerTable:                 0x10090c40,
				SEHandlerCount:                 0x3,
				GuardCFCheckFunctionPointer:    0x101f7b08,
				GuardCFFunctionTable:           0x1005ab70,
				GuardCFFunctionCount:           0xc4a,
				GuardFlags:                     0x10017500,
				GuardAddressTakenIatEntryTable: 0x1005e8e4,
				GuardAddressTakenIatEntryCount: 0xa,
				VolatileMetadataPointer:        0x10090c4c,
			},
		},
		{
			in: getAbsoluteFilePath("test/WdfCoInstaller01011.dll"),
			out: ImageLoadConfigDirectory64{
				Size:           0x70,
				SecurityCookie: 0x18000f108,
			},
		},
		{
			in: getAbsoluteFilePath("test/D2D1Debug2.dll"),
			out: ImageLoadConfigDirectory64{
				Size:                        0x94,
				SecurityCookie:              0x180061008,
				GuardCFCheckFunctionPointer: 0x180001000,
			},
		},
		{
			in: getAbsoluteFilePath("test/amdxata.sys"),
			out: ImageLoadConfigDirectory64{
				Size:                           0xa0,
				SecurityCookie:                 0x1c00030b0,
				GuardCFCheckFunctionPointer:    0x1c0005160,
				GuardCFDispatchFunctionPointer: 0x1c0005168,
				GuardCFFunctionTable:           0x1c0009000,
				GuardCFFunctionCount:           0x17,
				GuardFlags:                     0x500,
			},
		},
		{
			in: getAbsoluteFilePath("test/amdi2c.sys"),
			out: ImageLoadConfigDirectory64{
				Size:                           0xd0,
				SecurityCookie:                 0x140009090,
				GuardCFCheckFunctionPointer:    0x140008100,
				GuardCFDispatchFunctionPointer: 0x140008108,
				GuardFlags:                     0x100,
			},
		},
		{
			in: getAbsoluteFilePath("test/brave.exe"),
			out: ImageLoadConfigDirectory64{
				Size:                           0x100,
				SecurityCookie:                 0x14017b648,
				GuardCFCheckFunctionPointer:    0x140191000,
				GuardCFDispatchFunctionPointer: 0x140191008,
				GuardCFFunctionTable:           0x14016b627,
				GuardCFFunctionCount:           0x561,
				GuardFlags:                     0x500,
			},
		},
		{
			in: getAbsoluteFilePath("test/shimeng.dll"),
			out: ImageLoadConfigDirectory64{
				Size:                           0x108,
				SecurityCookie:                 0x180003000,
				GuardCFCheckFunctionPointer:    0x180002188,
				GuardCFDispatchFunctionPointer: 0x180002190,
				GuardCFFunctionTable:           0x180002198,
				GuardCFFunctionCount:           0x3,
				GuardFlags:                     0x17500,
			},
		},
		{
			in: getAbsoluteFilePath("test/kernel32.dll"),
			out: ImageLoadConfigDirectory64{
				Size:                           0x118,
				SecurityCookie:                 0x1800b3220,
				GuardCFCheckFunctionPointer:    0x180084218,
				GuardCFDispatchFunctionPointer: 0x180084220,
				GuardCFFunctionTable:           0x180084388,
				GuardCFFunctionCount:           0x5e6,
				GuardFlags:                     0x10417500,
				GuardAddressTakenIATEntryTable: 0x180086108,
				GuardAddressTakenIATEntryCount: 0x3,
				GuardEHContinuationTable:       0x180084228,
				GuardEHContinuationCount:       0x46,
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
				t.Fatalf("load config directory structure assertion failed, got %v, want %v",
					imgLoadCfgDirectory, tt.out)
			}

		})
	}
}

func TestLoadConfigDirectorySEHHandlers(t *testing.T) {

	tests := []struct {
		in  string
		out []uint32
	}{
		{
			in:  getAbsoluteFilePath("test/KernelBase.dll"),
			out: []uint32{0x14ad30, 0x14af40, 0x14b0d0},
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

			sehHandlers := file.LoadConfig.SEH
			if !reflect.DeepEqual(sehHandlers, tt.out) {
				t.Fatalf("load config SEH handlers assertion failed, got %v, want %v",
					sehHandlers, tt.out)
			}
		})
	}
}

func TestLoadConfigDirectoryControlFlowGuardFunctions(t *testing.T) {

	type TestGFIDSEntry struct {
		entriesCount int
		entryIndex   int
		CFGFunction  CFGFunction
	}

	tests := []struct {
		in  string
		out TestGFIDSEntry
	}{
		{
			in: getAbsoluteFilePath("test/KernelBase.dll"),
			out: TestGFIDSEntry{
				entriesCount: 0xc4a,
				entryIndex:   0x1,
				CFGFunction: CFGFunction{
					RVA:         0xfe2a0,
					Flags:       ImageGuardFlagExportSuppressed,
					Description: "GetCalendarInfoEx",
				},
			},
		},
		{
			in: getAbsoluteFilePath("test/kernel32.dll"),
			out: TestGFIDSEntry{
				entriesCount: 0x5e6,
				entryIndex:   0x5d3,
				CFGFunction: CFGFunction{
					RVA:         0x71390,
					Flags:       ImageGuardFlagExportSuppressed,
					Description: "QuirkIsEnabledForPackage2Worker",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {

			ops := Options{Fast: false}
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

			gfids := file.LoadConfig.GFIDS
			if len(gfids) != tt.out.entriesCount {
				t.Fatalf("load config GFIDS entries count assert failed, got %v, want %v",
					len(gfids), tt.out.entriesCount)
			}

			guardedFunction := gfids[tt.out.entryIndex]
			if !reflect.DeepEqual(guardedFunction, tt.out.CFGFunction) {
				t.Fatalf("load config GFIDS entry assertion failed, got %v, want %v",
					guardedFunction, tt.out.CFGFunction)
			}
		})
	}
}

func TestLoadConfigDirectoryControlFlowGuardIAT(t *testing.T) {

	type TestGFIDSEntry struct {
		entriesCount int
		entryIndex   int
		CFGFunction  CFGIATEntry
	}

	tests := []struct {
		in  string
		out TestGFIDSEntry
	}{
		{
			in: getAbsoluteFilePath("test/KernelBase.dll"),
			out: TestGFIDSEntry{
				entriesCount: 0xa,
				entryIndex:   0x9,
				CFGFunction: CFGIATEntry{
					RVA:         0x1f7924,
					IATValue:    0x80000008,
					INTValue:    0x80000008,
					Description: "ntdll.dll!#8",
				},
			},
		},
		{
			in: getAbsoluteFilePath("test/kernel32.dll"),
			out: TestGFIDSEntry{
				entriesCount: 0x3,
				entryIndex:   0x2,
				CFGFunction: CFGIATEntry{
					RVA:         0x83838,
					IATValue:    0xac0e0,
					INTValue:    0xac0e0,
					Description: "ntdll.dll!RtlGetLengthWithoutLastFullDosOrNtPathElement",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {

			ops := Options{Fast: false}
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

			cfgIAT := file.LoadConfig.CFGIAT
			if len(cfgIAT) != tt.out.entriesCount {
				t.Fatalf("load config CFG IAT entries count assert failed, got %v, want %v",
					len(cfgIAT), tt.out.entriesCount)
			}

			cfgIATEntry := cfgIAT[tt.out.entryIndex]
			if !reflect.DeepEqual(cfgIATEntry, tt.out.CFGFunction) {
				t.Fatalf("load config CFG IAT entry assertion failed, got %v, want %v",
					cfgIATEntry, tt.out.CFGFunction)
			}
		})
	}
}

func TestLoadConfigDirectoryControlFlowGuardLongJump(t *testing.T) {

	tests := []struct {
		in  string
		out []uint32
	}{
		{
			in: getAbsoluteFilePath("test/IEAdvpack.dll"),
			out: []uint32{0x13EDD, 0x1434F},
		},
		{
			in: getAbsoluteFilePath("test/PSCRIPT5.dll"),
			out: []uint32{0x3FE11, 0x401F8, 0x4077D, 0x40B53, 0x40DFD, 0x40FB3},
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

			cfgLongJumpTargetTable := file.LoadConfig.CFGLongJump
			if !reflect.DeepEqual(cfgLongJumpTargetTable, tt.out) {
				t.Fatalf("load config CFG long jump target table assertion failed, got %v, want %v",
				cfgLongJumpTargetTable, tt.out)
			}
		})
	}
}

