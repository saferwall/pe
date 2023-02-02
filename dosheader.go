// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"encoding/binary"
)

// ImageDOSHeader represents the DOS stub of a PE.
type ImageDOSHeader struct {
	// Magic number.
	Magic uint16 `json:"magic"`

	// Bytes on last page of file.
	BytesOnLastPageOfFile uint16 `json:"bytes_on_last_page_of_file"`

	// Pages in file.
	PagesInFile uint16 `json:"pages_in_file"`

	// Relocations.
	Relocations uint16 `json:"relocations"`

	// Size of header in paragraphs.
	SizeOfHeader uint16 `json:"size_of_header"`

	// Minimum extra paragraphs needed.
	MinExtraParagraphsNeeded uint16 `json:"min_extra_paragraphs_needed"`

	// Maximum extra paragraphs needed.
	MaxExtraParagraphsNeeded uint16 `json:"max_extra_paragraphs_needed"`

	// Initial (relative) SS value.
	InitialSS uint16 `json:"initial_ss"`

	// Initial SP value.
	InitialSP uint16 `json:"initial_sp"`

	// Checksum.
	Checksum uint16 `json:"checksum"`

	// Initial IP value.
	InitialIP uint16 `json:"initial_ip"`

	// Initial (relative) CS value.
	InitialCS uint16 `json:"initial_cs"`

	// File address of relocation table.
	AddressOfRelocationTable uint16 `json:"address_of_relocation_table"`

	// Overlay number.
	OverlayNumber uint16 `json:"overlay_number"`

	// Reserved words.
	ReservedWords1 [4]uint16 `json:"reserved_words_1"`

	// OEM identifier.
	OEMIdentifier uint16 `json:"oem_identifier"`

	// OEM information.
	OEMInformation uint16 `json:"oem_information"`

	// Reserved words.
	ReservedWords2 [10]uint16 `json:"reserved_words_2"`

	// File address of new exe header (Elfanew).
	AddressOfNewEXEHeader uint32 `json:"address_of__new_exe_header"`
}

// ParseDOSHeader parses the DOS header stub. Every PE file begins with a small
// MS-DOS stub. The need for this arose in the early days of Windows, before a
// significant number of consumers were running it. When executed on a machine
// without Windows, the program could at least print out a message saying that
// Windows was required to run the executable.
func (pe *File) ParseDOSHeader() (err error) {
	offset := uint32(0)
	size := uint32(binary.Size(pe.DOSHeader))
	err = pe.structUnpack(&pe.DOSHeader, offset, size)
	if err != nil {
		return err
	}

	// It can be ZM on an (non-PE) EXE.
	// These executables still work under XP via ntvdm.
	if pe.DOSHeader.Magic != ImageDOSSignature &&
		pe.DOSHeader.Magic != ImageDOSZMSignature {
		return ErrDOSMagicNotFound
	}

	// `e_lfanew` is the only required element (besides the signature) of the
	// DOS header to turn the EXE into a PE. It is is a relative offset to the
	// NT Headers. It can't be null (signatures would overlap).
	// Can be 4 at minimum.
	if pe.DOSHeader.AddressOfNewEXEHeader < 4 ||
		pe.DOSHeader.AddressOfNewEXEHeader > pe.size {
		return ErrInvalidElfanewValue
	}

	// tiny pe has a e_lfanew of 4, which means the NT Headers is overlapping
	// the DOS Header.
	if pe.DOSHeader.AddressOfNewEXEHeader <= 0x3c {
		pe.Anomalies = append(pe.Anomalies, AnoPEHeaderOverlapDOSHeader)
	}

	pe.HasDOSHdr = true
	return nil
}
