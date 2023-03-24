// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"sort"
	"strconv"
	"testing"
)

func TestClrDirectoryHeaders(t *testing.T) {

	type TestClrHeaders struct {
		clrHeader            ImageCOR20Header
		mdHeader             MetadataHeader
		mdStreamHeaders      []MetadataStreamHeader
		mdTablesStreamHeader MetadataTableStreamHeader
	}

	tests := []struct {
		in  string
		out TestClrHeaders
	}{
		{
			getAbsoluteFilePath("test/mscorlib.dll"),
			TestClrHeaders{
				clrHeader: ImageCOR20Header{
					Cb:                  0x48,
					MajorRuntimeVersion: 0x2,
					MinorRuntimeVersion: 0x5,
					MetaData: ImageDataDirectory{
						VirtualAddress: 0x2050,
						Size:           0xae34,
					},
					Flags:                0x9,
					EntryPointRVAorToken: 0x0,
					StrongNameSignature: ImageDataDirectory{
						VirtualAddress: 0xce84,
						Size:           0x80,
					},
				},
				mdHeader: MetadataHeader{
					Signature:     0x424a5342,
					MajorVersion:  0x1,
					MinorVersion:  0x1,
					ExtraData:     0x0,
					VersionString: 0xc,
					Version:       "v4.0.30319",
					Flags:         0x0,
					Streams:       0x5,
				},
				mdStreamHeaders: []MetadataStreamHeader{
					{
						Offset: 0x6c,
						Size:   0x4c38,
						Name:   "#~",
					},
					{
						Offset: 0x4ca4,
						Size:   0x5ed4,
						Name:   "#Strings",
					},
					{
						Offset: 0xab78,
						Size:   0x4,
						Name:   "#US",
					},
					{
						Offset: 0xab7c,
						Size:   0x10,
						Name:   "#GUID",
					},
					{
						Offset: 0xab8c,
						Size:   0x2a8,
						Name:   "#Blob",
					},
				},
				mdTablesStreamHeader: MetadataTableStreamHeader{
					Reserved:     0x0,
					MajorVersion: 0x2,
					MinorVersion: 0x0,
					Heaps:        0x0,
					RID:          0x1,
					MaskValid:    0x8900005407,
					Sorted:       0x16003301fa00,
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
			switch file.Is64 {
			case true:
				oh64 := file.NtHeader.OptionalHeader.(ImageOptionalHeader64)
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryCLR]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			case false:
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryCLR]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseCLRHeaderDirectory(va, size)
			if err != nil {
				t.Fatalf("parseCLRHeaderDirectory(%s) failed, reason: %v", tt.in, err)
			}
			clr := file.CLR
			if clr.CLRHeader != tt.out.clrHeader {
				t.Errorf("CLR header assertion failed, got %v, want %v",
					clr.CLRHeader, tt.out.clrHeader)
			}

			if clr.MetadataHeader != tt.out.mdHeader {
				t.Errorf("CLR metadata header assertion failed, got %v, want %v",
					clr.MetadataHeader, tt.out.mdHeader)
			}

			if !reflect.DeepEqual(clr.MetadataStreamHeaders, tt.out.mdStreamHeaders) {
				t.Errorf("CLR metadata stream headers assertion failed, got %v, want %v",
					clr.MetadataStreamHeaders, tt.out.mdStreamHeaders)
			}
		})
	}
}

func TestClrDirectoryMetadataTables(t *testing.T) {

	type TestClrMetadataTables struct {
		tableKind int
		table     MetadataTable
	}

	tests := []struct {
		in  string
		out TestClrMetadataTables
	}{
		{
			getAbsoluteFilePath("test/mscorlib.dll"),
			TestClrMetadataTables{
				tableKind: Module,
				table: MetadataTable{
					Name:      "Module",
					CountCols: 0x1,
					Content: ModuleTableRow{
						Generation: 0x0,
						Name:       0x2cd7,
						Mvid:       0x1,
						EncID:      0x0,
						EncBaseID:  0x0,
					},
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
			switch file.Is64 {
			case true:
				oh64 := file.NtHeader.OptionalHeader.(ImageOptionalHeader64)
				dirEntry := oh64.DataDirectory[ImageDirectoryEntryCLR]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			case false:
				oh32 := file.NtHeader.OptionalHeader.(ImageOptionalHeader32)
				dirEntry := oh32.DataDirectory[ImageDirectoryEntryCLR]
				va = dirEntry.VirtualAddress
				size = dirEntry.Size
			}

			err = file.parseCLRHeaderDirectory(va, size)
			if err != nil {
				t.Fatalf("parseCLRHeaderDirectory(%s) failed, reason: %v", tt.in, err)
			}

			clr := file.CLR
			mdTable := clr.MetadataTables[tt.out.tableKind]
			if !reflect.DeepEqual(*mdTable, tt.out.table) {
				t.Errorf("CLR metadata tables assertion failed, got %v, want %v",
					clr.MetadataTables, tt.out.table)
			}
		})
	}
}

func TestClrDirectorCOMImageFlagsType(t *testing.T) {

	tests := []struct {
		in  int
		out []string
	}{
		{
			0x9,
			[]string{"IL Only", "Strong Name Signed"},
		},
	}

	for _, tt := range tests {
		t.Run("CaseFlagsEqualTo_"+strconv.Itoa(tt.in), func(t *testing.T) {
			got := COMImageFlagsType(tt.in).String()
			got = sort.StringSlice(got)
			tt.out = sort.StringSlice(tt.out)
			if !reflect.DeepEqual(got, tt.out) {
				t.Errorf("CLR header flags assertion failed, got %v, want %v",
					got, tt.out)
			}
		})
	}
}
