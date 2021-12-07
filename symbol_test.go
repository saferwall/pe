// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import "testing"

type TestCOFFSymbol struct {
	errTooManySymbols error
	symbolsCount      int
	symbol            COFFSymbol
	stringTableOffset uint32
	symbolName        string
	sectionNumberName string
	symbolTypeString  string
}

var symbolTests = []struct {
	in  string
	out TestCOFFSymbol
}{
	{
		getAbsoluteFilePath("test/liblzo2-2"),
		TestCOFFSymbol{
			errTooManySymbols: nil,
			symbolsCount: 50,
			symbol: COFFSymbol{
				Name:               [8]byte{0, 0, 0, 0, 4, 0, 0, 0},
				Value:              0x2ac,
				SectionNumber:      8,
				Type:               0x0,
				StorageClass:       0x2,
				NumberOfAuxSymbols: 0x0,
			},
			stringTableOffset: 0x35184,
			symbolName:        "__imp_abort",
			sectionNumberName: ".idata",
			symbolTypeString:  "Null",
		},
	},

	{
		getAbsoluteFilePath("test/0000e876c5b712b6b7b3ce97f757ddd918fb3dbdc5a3938e850716fbd841309f"),
		TestCOFFSymbol{
			errTooManySymbols: errCOFFSymbolsTooHigh,
		},
	},
}

func TestParseCOFFSymbolTable(t *testing.T) {
	for _, tt := range symbolTests {
		t.Run(tt.in, func(t *testing.T) {
			ops := Options{Fast: true}
			file, err := New(tt.in, &ops)
			if err != nil {
				t.Errorf("TestParseCOFFSymbolTable(%s) failed, reason: %v", tt.in, err)
				return
			}
			err = file.Parse()
			if err != nil {
				t.Errorf("TestParseCOFFSymbolTable(%s) failed, reason: %v", tt.in, err)
				return
			}
			err = file.ParseCOFFSymbolTable()
			if err != tt.out.errTooManySymbols {
				t.Errorf("TestParseCOFFSymbolTable(%s) failed, reason: %v", tt.in, tt.out.errTooManySymbols)
			}

			if file.COFF == nil {
				return
			}

			if len(file.COFF.SymbolTable) != tt.out.symbolsCount {
				t.Errorf("TestParseCOFFSymbolTable(%s) failed, want: %d, got: %d", tt.in, tt.out.symbolsCount, len(file.COFF.SymbolTable))
			}
			if file.COFF.StringTableOffset != tt.out.stringTableOffset {
				t.Errorf("TestParseCOFFSymbolTable(%s) failed, want: %d, got: %d", tt.in, tt.out.stringTableOffset, file.COFF.StringTableOffset)
			}
			if !stringInSlice(tt.out.symbolName, file.COFF.StringTable) {
				t.Errorf("TestParseCOFFSymbolTable(%s) failed, want: %s, got: %v", tt.in, tt.out.symbolName, file.COFF.StringTable)
			}

			coffSymbol := file.COFF.SymbolTable[0]
			symbolNameStr, err := coffSymbol.String(file)
			if err != nil {
				t.Errorf("TestParseCOFFSymbolTable(%s) failed, COFFSymbol.String() failed with: %v", tt.in, err)
			}
			if symbolNameStr != tt.out.symbolName {
				t.Errorf("TestParseCOFFSymbolTable(%s) failed, want: %d, got: %d", tt.in, tt.out.symbolsCount, len(file.COFF.SymbolTable))
			}

			secNumName := coffSymbol.SectionNumberName(file)
			if secNumName != tt.out.sectionNumberName {
				t.Errorf("TestParseCOFFSymbolTable(%s) failed, want: %s, got: %s", tt.in, tt.out.sectionNumberName, secNumName)
			}

			typeString := file.PrettyCOFFTypeRepresentation(coffSymbol.Type)
			if typeString != tt.out.symbolTypeString {
				t.Errorf("TestParseCOFFSymbolTable(%s) failed, want: %s, got: %s", tt.in, tt.out.symbolTypeString, typeString)
			}
		})
	}
}
