// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"reflect"
	"sort"
	"testing"
)

type TestSection struct {
	sectionCount int
	sectionIndex int
	sectionName  string
	header       ImageSectionHeader
	sectionFlags []string
	entropy      float64
}

func TestParseSectionHeaders(t *testing.T) {

	tests := []struct {
		in  string
		out TestSection
	}{
		{getAbsoluteFilePath("test/putty.exe"),
			TestSection{
				sectionCount: 8,
				sectionIndex: 3,
				sectionName:  ".pdata",
				header: ImageSectionHeader{
					Name:             [8]uint8{0x2e, 0x70, 0x64, 0x61, 0x74, 0x61, 0x0, 0x0},
					VirtualSize:      0x588c,
					VirtualAddress:   0xd2000,
					SizeOfRawData:    0x5a00,
					PointerToRawData: 0xc9c00,
					Characteristics:  0x40000040,
				},
				sectionFlags: []string{"Initialized Data", "Readable"},
				entropy:      5.789589357441211,
			}},
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

			sections := file.Sections
			if len(sections) != tt.out.sectionCount {
				t.Errorf("sections count assertion failed, got %v, want %v",
					len(sections), tt.out.sectionCount)
			}

			section := sections[tt.out.sectionIndex]
			if !reflect.DeepEqual(section.Header, tt.out.header) {
				t.Errorf("section header assertion failed, got %v, want %v",
					section.Header, tt.out.header)
			}

			sectionName := sections[tt.out.sectionIndex].String()
			if sectionName != tt.out.sectionName {
				t.Errorf("section name assertion failed, got %v, want %v",
					sectionName, tt.out.sectionName)
			}

			prettySectionFlags := section.PrettySectionFlags()
			sort.Strings(prettySectionFlags)
			if !reflect.DeepEqual(prettySectionFlags, tt.out.sectionFlags) {
				t.Errorf("pretty section flags assertion failed, got %v, want %v",
					prettySectionFlags, tt.out.sectionFlags)
			}

			entropy := sections[tt.out.sectionIndex].CalculateEntropy(file)
			if entropy != tt.out.entropy {
				t.Errorf("entropy calculation failed, got %v, want %v",
					entropy, tt.out.entropy)
			}
		})
	}
}
