// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"encoding/binary"
	"errors"
)

var (
	// ErrInvalidBaseRelocVA is reposed when base reloc lies outside of the image.
	ErrInvalidBaseRelocVA = errors.New("invalid relocation information." +
		" Base Relocation VirtualAddress is outside of PE Image")

	// ErrInvalidBasicRelocSizeOfBloc is reposed when base reloc is too large.
	ErrInvalidBasicRelocSizeOfBloc = errors.New("invalid relocation " +
		"information. Base Relocation SizeOfBlock too large")
)

// ImageBaseRelocationEntryType represents the type of an in image base relocation entry.
type ImageBaseRelocationEntryType uint8

// The Type field of the relocation record indicates what kind of relocation
// should be performed. Different relocation types are defined for each type
// of machine.
const (
	// The base relocation is skipped. This type can be used to pad a block.
	ImageRelBasedAbsolute = 0

	// The base relocation adds the high 16 bits of the difference to the 16-bit
	// field at offset. The 16-bit field represents the high value of a 32-bit word.
	ImageRelBasedHigh = 1

	// The base relocation adds the low 16 bits of the difference to the 16-bit
	// field at offset. The 16-bit field represents the low half of a 32-bit word.
	ImageRelBasedLow = 2

	// The base relocation applies all 32 bits of the difference to the 32-bit
	// field at offset.
	ImageRelBasedHighLow = 3

	// The base relocation adds the high 16 bits of the difference to the 16-bit
	// field at offset. The 16-bit field represents the high value of a 32-bit
	// word. The low 16 bits of the 32-bit value are stored in the 16-bit word
	// that follows this base relocation. This means that this base relocation
	// occupies two slots.
	ImageRelBasedHighAdj = 4

	// The relocation interpretation is dependent on the machine type.
	// When the machine type is MIPS, the base relocation applies to a MIPS jump
	// instruction.
	ImageRelBasedMIPSJmpAddr = 5

	// This relocation is meaningful only when the machine type is ARM or Thumb.
	// The base relocation applies the 32-bit address of a symbol across a
	// consecutive MOVW/MOVT instruction pair.
	ImageRelBasedARMMov32 = 5

	// This relocation is only meaningful when the machine type is RISC-V. The
	// base relocation applies to the high 20 bits of a 32-bit absolute address.
	ImageRelBasedRISCVHigh20 = 5

	// Reserved, must be zero.
	ImageRelReserved = 6

	// This relocation is meaningful only when the machine type is Thumb.
	// The base relocation applies the 32-bit address of a symbol to a
	// consecutive MOVW/MOVT instruction pair.
	ImageRelBasedThumbMov32 = 7

	// This relocation is only meaningful when the machine type is RISC-V.
	// The base relocation applies to the low 12 bits of a 32-bit absolute
	// address formed in RISC-V I-type instruction format.
	ImageRelBasedRISCVLow12i = 7

	// This relocation is only meaningful when the machine type is RISC-V.
	// The base relocation applies to the low 12 bits of a 32-bit absolute
	// address formed in RISC-V S-type instruction format.
	ImageRelBasedRISCVLow12s = 8

	// The relocation is only meaningful when the machine type is MIPS.
	// The base relocation applies to a MIPS16 jump instruction.
	ImageRelBasedMIPSJmpAddr16 = 9

	// The base relocation applies the difference to the 64-bit field at offset.
	ImageRelBasedDir64 = 10
)

const (
	// MaxDefaultRelocEntriesCount represents the default maximum number of
	// relocations entries to parse. Some malware uses a fake huge reloc entries that
	// can slow significantly the parser.
	// Example:  01008963d32f5cc17b64c31446386ee5b36a7eab6761df87a2989ba9394d8f3d
	MaxDefaultRelocEntriesCount = 0x1000
)

// ImageBaseRelocation represents the IMAGE_BASE_RELOCATION structure.
// Each chunk of base relocation data begins with an IMAGE_BASE_RELOCATION structure.
type ImageBaseRelocation struct {
	// The image base plus the page RVA is added to each offset to create the
	// VA where the base relocation must be applied.
	VirtualAddress uint32 `json:"virtual_address"`

	// The total number of bytes in the base relocation block, including the
	// Page RVA and Block Size fields and the Type/Offset fields that follow.
	SizeOfBlock uint32 `json:"size_of_block"`
}

// ImageBaseRelocationEntry represents an image base relocation entry.
type ImageBaseRelocationEntry struct {
	// Locate data that must be reallocated in buffer (data being an address
	// we use pointer of pointer).
	Data uint16 `json:"data"`

	// The offset of the relocation. This value plus the VirtualAddress
	// in IMAGE_BASE_RELOCATION is the complete RVA.
	Offset uint16 `json:"offset"`

	// A value that indicates the kind of relocation that should be performed.
	// Valid relocation types depend on machine type.
	Type ImageBaseRelocationEntryType `json:"type"`
}

// Relocation represents the relocation table which holds the data that needs to
// be relocated.
type Relocation struct {
	// Points to the ImageBaseRelocation structure.
	Data ImageBaseRelocation `json:"data"`

	// holds the list of entries for each chunk.
	Entries []ImageBaseRelocationEntry `json:"entries"`
}

func (pe *File) parseRelocations(dataRVA, rva, size uint32) ([]ImageBaseRelocationEntry, error) {
	var relocEntries []ImageBaseRelocationEntry

	relocEntriesCount := size / 2
	if relocEntriesCount > pe.opts.MaxRelocEntriesCount {
		pe.Anomalies = append(pe.Anomalies, AnoAddressOfDataBeyondLimits)
	}

	offset := pe.GetOffsetFromRva(dataRVA)
	var err error
	for i := uint32(0); i < relocEntriesCount; i++ {
		entry := ImageBaseRelocationEntry{}
		entry.Data, err = pe.ReadUint16(offset + (i * 2))
		if err != nil {
			break
		}
		entry.Type = ImageBaseRelocationEntryType(entry.Data >> 12)
		entry.Offset = entry.Data & 0x0fff
		relocEntries = append(relocEntries, entry)
	}

	return relocEntries, nil
}

func (pe *File) parseRelocDirectory(rva, size uint32) error {
	var sizeOfImage uint32
	switch pe.Is64 {
	case true:
		sizeOfImage = pe.NtHeader.OptionalHeader.(ImageOptionalHeader64).SizeOfImage
	case false:
		sizeOfImage = pe.NtHeader.OptionalHeader.(ImageOptionalHeader32).SizeOfImage
	}

	relocSize := uint32(binary.Size(ImageBaseRelocation{}))
	end := rva + size
	for rva < end {
		baseReloc := ImageBaseRelocation{}
		offset := pe.GetOffsetFromRva(rva)
		err := pe.structUnpack(&baseReloc, offset, relocSize)
		if err != nil {
			return err
		}

		// VirtualAddress must lie within the Image.
		if baseReloc.VirtualAddress > sizeOfImage {
			return ErrInvalidBaseRelocVA
		}

		// SizeOfBlock must be less or equal than the size of the image.
		// It's a rather loose sanity test.
		if baseReloc.SizeOfBlock > sizeOfImage {
			return ErrInvalidBasicRelocSizeOfBloc
		}

		relocEntries, err := pe.parseRelocations(rva+relocSize,
			baseReloc.VirtualAddress, baseReloc.SizeOfBlock-relocSize)
		if err != nil {
			return err
		}

		pe.Relocations = append(pe.Relocations, Relocation{
			Data:    baseReloc,
			Entries: relocEntries,
		})

		if baseReloc.SizeOfBlock == 0 {
			break
		}
		rva += baseReloc.SizeOfBlock
	}

	if len(pe.Relocations) > 0 {
		pe.HasReloc = true
	}

	return nil
}

// String returns the string representation of the `Type` field of a base reloc entry.
func (t ImageBaseRelocationEntryType) String(pe *File) string {
	relocTypesMap := map[ImageBaseRelocationEntryType]string{
		ImageRelBasedAbsolute:      "Absolute",
		ImageRelBasedHigh:          "High",
		ImageRelBasedLow:           "Low",
		ImageRelBasedHighLow:       "HighLow",
		ImageRelBasedHighAdj:       "HighAdj",
		ImageRelReserved:           "Reserved",
		ImageRelBasedRISCVLow12s:   "RISC-V Low12s",
		ImageRelBasedMIPSJmpAddr16: "MIPS Jmp Addr16",
		ImageRelBasedDir64:         "DIR64",
	}

	if value, ok := relocTypesMap[t]; ok {
		return value
	}

	switch pe.NtHeader.FileHeader.Machine {
	case ImageFileMachineMIPS16, ImageFileMachineMIPSFPU, ImageFileMachineMIPSFPU16, ImageFileMachineWCEMIPSv2:
		if t == ImageRelBasedMIPSJmpAddr {
			return "MIPS JMP Addr"
		}

	case ImageFileMachineARM, ImageFileMachineARM64, ImageFileMachineARMNT:
		if t == ImageRelBasedARMMov32 {
			return "ARM MOV 32"
		}

		if t == ImageRelBasedThumbMov32 {
			return "Thumb MOV 32"
		}
	case ImageFileMachineRISCV32, ImageFileMachineRISCV64, ImageFileMachineRISCV128:
		if t == ImageRelBasedRISCVHigh20 {
			return "RISC-V High 20"
		}

		if t == ImageRelBasedRISCVLow12i {
			return "RISC-V Low 12"
		}
	}

	return "?"
}
