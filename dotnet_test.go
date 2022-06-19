// Copyright 2022 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"testing"
)

type TestClrEntry struct {
	clrHeader            *ImageCOR20Header
	mdHeader             *MetadataHeader
	mdStreamHeaders      []*MetadataStreamHeader
	mdStreamsCount       int
	mdStreamName         string
	mdStream             []byte
	mdTablesStreamHeader *MetadataTableStreamHeader
	mdTables             map[int]*MetadataTable
}

func TestDotNet(t *testing.T) {

	tests := []struct {
		in  string
		out TestClrEntry
	}{
		{
			getAbsoluteFilePath("test/mscorlib.dll"),
			TestClrEntry{
				clrHeader: &ImageCOR20Header{
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
				mdHeader: &MetadataHeader{
					Signature:     0x424a5342,
					MajorVersion:  0x1,
					MinorVersion:  0x1,
					ExtraData:     0x0,
					VersionString: 0xc,
					Version:       "v4.0.30319",
					Flags:         0x0,
					Streams:       0x5,
				},
				mdStreamHeaders: []*MetadataStreamHeader{
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
				mdStreamsCount: 5,
				mdStreamName:   "#GUID",
				mdStream: []byte{
					0x4c, 0xd8, 0x30, 0x51, 0xe8, 0x48, 0x80, 0x45, 0x9a,
					0x3b, 0x20, 0xe8, 0xaf, 0xf8, 0xbe, 0xdf,
				},
				mdTablesStreamHeader: &MetadataTableStreamHeader{
					Reserved:     0x0,
					MajorVersion: 0x2,
					MinorVersion: 0x0,
					Heaps:        0x0,
					Rid:          0x1,
					MaskValid:    0x8900005407,
					Sorted:       0x16003301fa00,
				},
				mdTables: map[int]*MetadataTable{
					12: {
						Name:       "CustomAttribute",
						CountCols:  0x13,
						SizeRecord: 0x0,
					},
					32: {
						Name:       "Assembly",
						CountCols:  0x1,
						SizeRecord: 0x0,
					},
					35: {
						Name:       "AssemblyRef",
						CountCols:  0x1e,
						SizeRecord: 0x0,
					},
					39: {
						Name:       "ExportedType",
						CountCols:  0x27,
						SizeRecord: 0x0,
					},
					0: {
						Name:       "Module",
						CountCols:  0x1,
						SizeRecord: 0x0,
						Content: ModuleTableRow{
							Generation: 0x0,
							Name:       0x2cd7,
							Mvid:       0x1,
							EncID:      0x0,
							EncBaseID:  0x0,
						},
					},
					1: {
						Name:       "TypeRef",
						CountCols:  0x13,
						SizeRecord: 0x0,
					},
					2: {
						Name:       "TypeDef",
						CountCols:  0x1,
						SizeRecord: 0x0,
					},
					10: {
						Name:       "MemberRef",
						CountCols:  0x11,
						SizeRecord: 0x0,
					},
					14: {
						Name:       "DeclSecurity",
						CountCols:  0x1,
						SizeRecord: 0x0,
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
			got := file.CLR
			if !reflect.DeepEqual(got.CLRHeader, tt.out.clrHeader) {
				t.Errorf("DotNET CLR header assertion failed, got %v, want %v",
					got.CLRHeader, tt.out.clrHeader)
			}

			if !reflect.DeepEqual(got.MetadataHeader, tt.out.mdHeader) {
				t.Errorf("DotNET Metadata header assertion failed, got %v, want %v",
					got.MetadataHeader, tt.out.mdHeader)
			}

			if !reflect.DeepEqual(got.MetadataStreamHeaders, tt.out.mdStreamHeaders) {
				t.Errorf("DotNET metadata stream headers assertion failed, got %v, want %v",
					got.MetadataStreamHeaders, tt.out.mdStreamHeaders)
			}

			if len(got.MetadataStreams) != tt.out.mdStreamsCount {
				t.Errorf("DotNET metadata streams count assertion failed, got %v, want %v",
					len(got.MetadataStreams), tt.out.mdStreamsCount)
			}

			if !reflect.DeepEqual(got.MetadataStreams[tt.out.mdStreamName], tt.out.mdStream) {
				t.Errorf("DotNET metadata stream [%s] assertion failed, got %v, want %v",
					tt.out.mdStreamName, got.MetadataStreams[tt.out.mdStreamName], tt.out.mdStream)
			}

			if !reflect.DeepEqual(got.MetadataTablesStreamHeader, tt.out.mdTablesStreamHeader) {
				t.Errorf("DotNET metadata tables stream header assertion failed, got %v, want %v",
					got.MetadataTablesStreamHeader, tt.out.mdTablesStreamHeader)
			}

			if !reflect.DeepEqual(got.MetadataTables, tt.out.mdTables) {
				t.Errorf("DotNET metadata tables assertion failed, got %v, want %v",
					got.MetadataTables, tt.out.mdTables)
			}
		})
	}
}
