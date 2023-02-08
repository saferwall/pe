// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"testing"
)

type TestRsrcDir struct {
	Level1ImgRsrcDir   ImageResourceDirectory
	Level2Index        int
	Level2ImgRsrcDir   ImageResourceDirectory
	Level3Index        int
	Level3ImgRsrcDir   ImageResourceDirectory
	Level3RsrcDirEntry ResourceDirectoryEntry
	Level4Index        int
	Level4RsrcDirEntry ResourceDirectoryEntry
}

func TestParseResourceDirectory(t *testing.T) {

	tests := []struct {
		in  string
		out TestRsrcDir
	}{
		{
			getAbsoluteFilePath("test/putty.exe"),
			TestRsrcDir{
				Level1ImgRsrcDir: ImageResourceDirectory{
					Characteristics:      0x0,
					TimeDateStamp:        0x0,
					MajorVersion:         0x0,
					MinorVersion:         0x0,
					NumberOfNamedEntries: 0x0,
					NumberOfIDEntries:    0x6,
				},
				Level2Index: 0x3,
				Level2ImgRsrcDir: ImageResourceDirectory{
					Characteristics:      0x0,
					TimeDateStamp:        0x0,
					MajorVersion:         0x0,
					MinorVersion:         0x0,
					NumberOfNamedEntries: 0x0,
					NumberOfIDEntries:    0x1,
				},
				Level3Index: 0x0,
				Level3ImgRsrcDir: ImageResourceDirectory{
					Characteristics:      0x0,
					TimeDateStamp:        0x0,
					MajorVersion:         0x0,
					MinorVersion:         0x0,
					NumberOfNamedEntries: 0x0,
					NumberOfIDEntries:    0x1,
				},
				Level4Index: 0x0,
				Level4RsrcDirEntry: ResourceDirectoryEntry{
					Struct: ImageResourceDirectoryEntry{
						Name:         0x409,
						OffsetToData: 0x460,
					},
					Name:          "",
					ID:            0x409,
					IsResourceDir: false,
					Data: ResourceDataEntry{
						Lang:    0x9,
						SubLang: 0x1,
						Struct: ImageResourceDataEntry{
							OffsetToData: 0x124838,
							Size:         0x324,
							CodePage:     0x0,
							Reserved:     0x0,
						},
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
			if rsrc.Struct != tt.out.Level1ImgRsrcDir {
				t.Fatalf("level 1 resource directory assertion failed, got %v, want %v",
					rsrc.Struct, tt.out.Level1ImgRsrcDir)
			}

			rsrcDirLevel2 := rsrc.Entries[tt.out.Level2Index].Directory
			if rsrcDirLevel2.Struct != tt.out.Level2ImgRsrcDir {
				t.Fatalf("level 2 resource directory assertion failed, got %v, want %v",
					rsrc.Struct, tt.out.Level2ImgRsrcDir)
			}

			rsrcDirLevel3 := rsrcDirLevel2.Entries[tt.out.Level3Index].Directory
			if rsrcDirLevel3.Struct != tt.out.Level3ImgRsrcDir {
				t.Fatalf("level 3 resource directory assertion failed, got %v, want %v",
					rsrc.Struct, tt.out.Level3ImgRsrcDir)
			}

			rsrcDirEntry := rsrcDirLevel3.Entries[tt.out.Level4Index]
			if !reflect.DeepEqual(rsrcDirEntry, tt.out.Level4RsrcDirEntry) {
				t.Fatalf("level 3 resource directory entry assertion failed, got %v, want %v",
					rsrc.Struct, tt.out.Level3ImgRsrcDir)
			}
		})
	}
}

func TestResourceTypeString(t *testing.T) {

	tests := []struct {
		in  ResourceType
		out string
	}{
		{
			RTCursor,
			"Cursor",
		},
		{
			ResourceType(0xff),
			"?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.out, func(t *testing.T) {

			rsrcTypeString := tt.in.String()
			if rsrcTypeString != tt.out {
				t.Fatalf("resource type string conversion failed, got %v, want %v",
					rsrcTypeString, tt.out)
			}
		})
	}
}

func TestResourceLangString(t *testing.T) {

	tests := []struct {
		in  ResourceLang
		out string
	}{
		{

			LangArabic,
			"Arabic (ar)",
		},
		{
			ResourceLang(0xffff),
			"?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.out, func(t *testing.T) {

			rsrcLangString := tt.in.String()
			if rsrcLangString != tt.out {
				t.Fatalf("resource language string conversion failed, got %v, want %v",
					rsrcLangString, tt.out)
			}
		})
	}
}

func TestResourceSubLangString(t *testing.T) {

	tests := []struct {
		in  ResourceSubLang
		out string
	}{
		{

			SubLangArabicMorocco,
			"Arabic Morocco (ar-MA)",
		},
		{
			ResourceSubLang(0xffff),
			"?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.out, func(t *testing.T) {

			rsrcSubLangString := tt.in.String()
			if rsrcSubLangString != tt.out {
				t.Fatalf("resource sub-language string conversion failed, got %v, want %v",
					rsrcSubLangString, tt.out)
			}
		})
	}
}

func TestPrettyResourceLang(t *testing.T) {

	type resourceLang struct {
		lang    ResourceLang
		subLang int
	}

	tests := []struct {
		in  resourceLang
		out string
	}{
		{
			resourceLang{
				lang:    LangEnglish,
				subLang: 0x1,
			},
			"English United States (en-US)",
		},
		{
			resourceLang{
				lang:    ResourceLang(0xff),
				subLang: 0x1,
			},
			"?",
		},
	}

	for _, tt := range tests {
		t.Run(tt.out, func(t *testing.T) {

			prettyRsrcLang := PrettyResourceLang(tt.in.lang, tt.in.subLang)
			if prettyRsrcLang != tt.out {
				t.Fatalf("pretty resource language failed, got %v, want %v",
					prettyRsrcLang, tt.out)
			}
		})
	}
}
