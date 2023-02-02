// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	imageOrdinalFlag32   = uint32(0x80000000)
	imageOrdinalFlag64   = uint64(0x8000000000000000)
	maxRepeatedAddresses = uint32(0xF)
	maxAddressSpread     = uint32(0x8000000)
	addressMask32        = uint32(0x7fffffff)
	addressMask64        = uint64(0x7fffffffffffffff)
	maxDllLength         = 0x200
	maxImportNameLength  = 0x200
)

var (
	// AnoInvalidThunkAddressOfData is reported when thunk address is too spread out.
	AnoInvalidThunkAddressOfData = "Thunk Address Of Data too spread out"

	// AnoManyRepeatedEntries is reported when import directory contains many
	// entries have the same RVA.
	AnoManyRepeatedEntries = "Import directory contains many repeated entries"

	// AnoAddressOfDataBeyondLimits is reported when Thunk AddressOfData goes
	// beyond limits.
	AnoAddressOfDataBeyondLimits = "Thunk AddressOfData beyond limits"

	// AnoImportNoNameNoOrdinal is reported when an import entry does not have
	// a name neither an ordinal, most probably malformed data.
	AnoImportNoNameNoOrdinal = "Must have either an ordinal or a name in an import"

	// ErrDamagedImportTable is reported when the IAT and ILT table length is 0.
	ErrDamagedImportTable = errors.New(
		"damaged Import Table information. ILT and/or IAT appear to be broken")
)

// ImageImportDescriptor describes the remainder of the import information.
// The import directory table contains address information that is used to
// resolve fixup references to the entry points within a DLL image.
// It consists of an array of import directory entries, one entry for each DLL
// to which the image refers. The last directory entry is empty (filled with
// null values), which indicates the end of the directory table.
type ImageImportDescriptor struct {
	// The RVA of the import lookup/name table (INT). This table contains a name
	// or ordinal for each import. The INT is an array of IMAGE_THUNK_DATA structs.
	OriginalFirstThunk uint32 `json:"original_first_thunk"`

	// The stamp that is set to zero until the image is bound. After the image
	// is bound, this field is set to the time/data stamp of the DLL.
	TimeDateStamp uint32 `json:"time_date_stamp"`

	// The index of the first forwarder reference (-1 if no forwarders).
	ForwarderChain uint32 `json:"forwarder_chain"`

	// The address of an ASCII string that contains the name of the DLL.
	// This address is relative to the image base.
	Name uint32 `json:"name"`

	// The RVA of the import address table (IAT). The contents of this table are
	// identical to the contents of the import lookup table until the image is bound.
	FirstThunk uint32 `json:"first_thunk"`
}

// ImageThunkData32 corresponds to one imported function from the executable.
// The entries are an array of 32-bit numbers for PE32 or an array of 64-bit
// numbers for PE32+. The ends of both arrays are indicated by an
// IMAGE_THUNK_DATA element with a value of zero.
// The IMAGE_THUNK_DATA union is a DWORD with these interpretations:
// DWORD Function;       // Memory address of the imported function
// DWORD Ordinal;        // Ordinal value of imported API
// DWORD AddressOfData;  // RVA to an IMAGE_IMPORT_BY_NAME with the imported API name
// DWORD ForwarderString;// RVA to a forwarder string
type ImageThunkData32 struct {
	AddressOfData uint32
}

// ImageThunkData64 is the PE32+ version of IMAGE_THUNK_DATA.
type ImageThunkData64 struct {
	AddressOfData uint64
}

type ThunkData32 struct {
	ImageThunkData ImageThunkData32
	Offset         uint32
}

type ThunkData64 struct {
	ImageThunkData ImageThunkData64
	Offset         uint32
}

// ImportFunction represents an imported function in the import table.
type ImportFunction struct {
	// An ASCII string that contains the name to import. This is the string that
	// must be matched to the public name in the DLL. This string is case
	// sensitive and terminated by a null byte.
	Name string `json:"name"`

	// An index into the export name pointer table. A match is attempted first
	// with this value. If it fails, a binary search is performed on the DLL's
	// export name pointer table.
	Hint uint16 `json:"hint"`

	// If this is true, import by ordinal. Otherwise, import by name.
	ByOrdinal bool `json:"by_ordinal"`

	// A 16-bit ordinal number. This field is used only if the Ordinal/Name Flag
	// bit field is 1 (import by ordinal). Bits 30-15 or 62-15 must be 0.
	Ordinal uint32 `json:"ordinal"`

	// Name Thunk Value (OFT)
	OriginalThunkValue uint64 `json:"original_thunk_value"`

	// Address Thunk Value (FT)
	ThunkValue uint64 `json:"thunk_value"`

	// Address Thunk RVA.
	ThunkRVA uint32 `json:"thunk_rva"`

	// Name Thunk RVA.
	OriginalThunkRVA uint32 `json:"original_thunk_rva"`
}

// Import represents an empty entry in the import table.
type Import struct {
	Offset     uint32                `json:"offset"`
	Name       string                `json:"name"`
	Functions  []ImportFunction      `json:"functions"`
	Descriptor ImageImportDescriptor `json:"descriptor"`
}

func (pe *File) parseImportDirectory(rva, size uint32) (err error) {

	for {
		importDesc := ImageImportDescriptor{}
		fileOffset := pe.GetOffsetFromRva(rva)
		importDescSize := uint32(binary.Size(importDesc))
		err := pe.structUnpack(&importDesc, fileOffset, importDescSize)

		// If the RVA is invalid all would blow up. Some EXEs seem to be
		// specially nasty and have an invalid RVA.
		if err != nil {
			return err
		}

		// If the structure is all zeros, we reached the end of the list.
		if importDesc == (ImageImportDescriptor{}) {
			break
		}

		rva += importDescSize

		// If the array of thunks is somewhere earlier than the import
		// descriptor we can set a maximum length for the array. Otherwise
		// just set a maximum length of the size of the file
		maxLen := uint32(len(pe.data)) - fileOffset
		if rva > importDesc.OriginalFirstThunk || rva > importDesc.FirstThunk {
			if rva < importDesc.OriginalFirstThunk {
				maxLen = rva - importDesc.FirstThunk
			} else if rva < importDesc.FirstThunk {
				maxLen = rva - importDesc.OriginalFirstThunk
			} else {
				maxLen = Max(rva-importDesc.OriginalFirstThunk,
					rva-importDesc.FirstThunk)
			}
		}

		var importedFunctions []ImportFunction
		if pe.Is64 {
			importedFunctions, err = pe.parseImports64(&importDesc, maxLen)
		} else {
			importedFunctions, err = pe.parseImports32(&importDesc, maxLen)
		}
		if err != nil {
			return err
		}

		dllName := pe.getStringAtRVA(importDesc.Name, maxDllLength)
		if !IsValidDosFilename(dllName) {
			dllName = "*invalid*"
			continue
		}

		pe.Imports = append(pe.Imports, Import{
			Offset:     fileOffset,
			Name:       string(dllName),
			Functions:  importedFunctions,
			Descriptor: importDesc,
		})
	}

	if len(pe.Imports) > 0 {
		pe.HasImport = true
	}

	return nil
}

func (pe *File) getImportTable32(rva uint32, maxLen uint32,
	isOldDelayImport bool) ([]ThunkData32, error) {

	// Setup variables
	thunkTable := make(map[uint32]*ImageThunkData32)
	retVal := []ThunkData32{}
	minAddressOfData := ^uint32(0)
	maxAddressOfData := uint32(0)
	repeatedAddress := uint32(0)
	var size uint32 = 4
	addressesOfData := make(map[uint32]bool)

	startRVA := rva

	if rva == 0 {
		return nil, nil
	}

	for {
		if rva >= startRVA+maxLen {
			pe.logger.Warnf("Error parsing the import table. Entries go beyond bounds.")
			break
		}

		// if we see too many times the same entry we assume it could be
		// a table containing bogus data (with malicious intent or otherwise)
		if repeatedAddress >= maxRepeatedAddresses {
			if !stringInSlice(AnoManyRepeatedEntries, pe.Anomalies) {
				pe.Anomalies = append(pe.Anomalies, AnoManyRepeatedEntries)
			}
		}

		// if the addresses point somewhere but the difference between the
		// highest and lowest address is larger than maxAddressSpread we assume
		// a bogus table as the addresses should be contained within a module
		if maxAddressOfData-minAddressOfData > maxAddressSpread {
			if !stringInSlice(AnoInvalidThunkAddressOfData, pe.Anomalies) {
				pe.Anomalies = append(pe.Anomalies, AnoInvalidThunkAddressOfData)
			}
		}

		// In its original incarnation in Visual C++ 6.0, all ImgDelayDescr
		// fields containing addresses used virtual addresses, rather than RVAs.
		// That is, they contained actual addresses where the delayload data
		// could be found. These fields are DWORDs, the size of a pointer on the x86.
		// Now fast-forward to IA-64 support. All of a sudden, 4 bytes isn't
		// enough to hold a complete address. At this point, Microsoft did the
		// correct thing and changed the fields containing addresses to RVAs.
		offset := uint32(0)
		if isOldDelayImport {
			oh32 := pe.NtHeader.OptionalHeader.(ImageOptionalHeader32)
			newRVA := rva - oh32.ImageBase
			offset = pe.GetOffsetFromRva(newRVA)
			if offset == ^uint32(0) {
				return nil, nil
			}
		} else {
			offset = pe.GetOffsetFromRva(rva)
			if offset == ^uint32(0) {
				return nil, nil
			}
		}

		// Read the image thunk data.
		thunk := ImageThunkData32{}
		err := pe.structUnpack(&thunk, offset, size)
		if err != nil {
			// pe.logger.Warnf("Error parsing the import table. " +
			// 	"Invalid data at RVA: 0x%x", rva)
			return nil, nil
		}

		if thunk == (ImageThunkData32{}) {
			break
		}

		// Check if the AddressOfData lies within the range of RVAs that it's
		// being scanned, abort if that is the case, as it is very unlikely
		// to be legitimate data.
		// Seen in PE with SHA256:
		// 5945bb6f0ac879ddf61b1c284f3b8d20c06b228e75ae4f571fa87f5b9512902c
		if thunk.AddressOfData >= startRVA && thunk.AddressOfData <= rva {
			pe.logger.Warnf("Error parsing the import table. "+
				"AddressOfData overlaps with THUNK_DATA for THUNK at: "+
				"RVA 0x%x", rva)
			break
		}

		if thunk.AddressOfData&imageOrdinalFlag32 > 0 {
			// If the entry looks like could be an ordinal.
			if thunk.AddressOfData&0x7fffffff > 0xffff {
				// but its value is beyond 2^16, we will assume it's a
				// corrupted and ignore it altogether
				if !stringInSlice(AnoAddressOfDataBeyondLimits, pe.Anomalies) {
					pe.Anomalies = append(pe.Anomalies, AnoAddressOfDataBeyondLimits)
				}
			}
		} else {
			// and if it looks like it should be an RVA keep track of the RVAs seen
			// and store them to study their  properties. When certain non-standard
			// features are detected the parsing will be aborted
			_, ok := addressesOfData[thunk.AddressOfData]
			if ok {
				repeatedAddress++
			} else {
				addressesOfData[thunk.AddressOfData] = true
			}

			if thunk.AddressOfData > maxAddressOfData {
				maxAddressOfData = thunk.AddressOfData
			}

			if thunk.AddressOfData < minAddressOfData {
				minAddressOfData = thunk.AddressOfData
			}
		}

		thunkTable[rva] = &thunk
		thunkData := ThunkData32{ImageThunkData: thunk, Offset: rva}
		retVal = append(retVal, thunkData)
		rva += size
	}
	return retVal, nil
}

func (pe *File) getImportTable64(rva uint32, maxLen uint32,
	isOldDelayImport bool) ([]ThunkData64, error) {

	// Setup variables
	thunkTable := make(map[uint32]*ImageThunkData64)
	retVal := []ThunkData64{}
	minAddressOfData := ^uint64(0)
	maxAddressOfData := uint64(0)
	repeatedAddress := uint64(0)
	var size uint32 = 8
	addressesOfData := make(map[uint64]bool)

	startRVA := rva

	if rva == 0 {
		return nil, nil
	}

	for {
		if rva >= startRVA+maxLen {
			pe.logger.Warnf("Error parsing the import table. Entries go beyond bounds.")
			break
		}

		// if we see too many times the same entry we assume it could be
		// a table containing bogus data (with malicious intent or otherwise)
		if repeatedAddress >= uint64(maxRepeatedAddresses) {
			if !stringInSlice(AnoManyRepeatedEntries, pe.Anomalies) {
				pe.Anomalies = append(pe.Anomalies, AnoManyRepeatedEntries)
			}
		}

		// if the addresses point somewhere but the difference between the highest
		// and lowest address is larger than maxAddressSpread we assume a bogus
		// table as the addresses should be contained within a module
		if maxAddressOfData-minAddressOfData > uint64(maxAddressSpread) {
			if !stringInSlice(AnoInvalidThunkAddressOfData, pe.Anomalies) {
				pe.Anomalies = append(pe.Anomalies, AnoInvalidThunkAddressOfData)
			}
		}

		// In its original incarnation in Visual C++ 6.0, all ImgDelayDescr
		// fields containing addresses used virtual addresses, rather than RVAs.
		// That is, they contained actual addresses where the delayload data
		// could be found. These fields are DWORDs, the size of a pointer on the x86.
		// Now fast-forward to IA-64 support. All of a sudden, 4 bytes isn't
		// enough to hold a complete address. At this point, Microsoft did the
		// correct thing and changed the fields containing addresses to RVAs.
		offset := uint32(0)
		if isOldDelayImport {
			oh64 := pe.NtHeader.OptionalHeader.(ImageOptionalHeader64)
			newRVA := rva - uint32(oh64.ImageBase)
			offset = pe.GetOffsetFromRva(newRVA)
			if offset == ^uint32(0) {
				return nil, nil
			}
		} else {
			offset = pe.GetOffsetFromRva(rva)
			if offset == ^uint32(0) {
				return nil, nil
			}
		}

		// Read the image thunk data.
		thunk := ImageThunkData64{}
		err := pe.structUnpack(&thunk, offset, size)
		if err != nil {
			// pe.logger.Warnf("Error parsing the import table. " +
			// 	"Invalid data at RVA: 0x%x", rva)
			return nil, nil
		}

		if thunk == (ImageThunkData64{}) {
			break
		}

		// Check if the AddressOfData lies within the range of RVAs that it's
		// being scanned, abort if that is the case, as it is very unlikely
		// to be legitimate data.
		// Seen in PE with SHA256:
		// 5945bb6f0ac879ddf61b1c284f3b8d20c06b228e75ae4f571fa87f5b9512902c
		if thunk.AddressOfData >= uint64(startRVA) &&
			thunk.AddressOfData <= uint64(rva) {
			pe.logger.Warnf("Error parsing the import table. "+
				"AddressOfData overlaps with THUNK_DATA for THUNK at: "+
				"RVA 0x%x", rva)
			break
		}

		// If the entry looks like could be an ordinal
		if thunk.AddressOfData&imageOrdinalFlag64 > 0 {
			// but its value is beyond 2^16, we will assume it's a
			// corrupted and ignore it altogether
			if thunk.AddressOfData&0x7fffffff > 0xffff {
				if !stringInSlice(AnoAddressOfDataBeyondLimits, pe.Anomalies) {
					pe.Anomalies = append(pe.Anomalies, AnoAddressOfDataBeyondLimits)
				}
			}
			// and if it looks like it should be an RVA
		} else {
			// keep track of the RVAs seen and store them to study their
			// properties. When certain non-standard features are detected
			// the parsing will be aborted
			_, ok := addressesOfData[thunk.AddressOfData]
			if ok {
				repeatedAddress++
			} else {
				addressesOfData[thunk.AddressOfData] = true
			}

			if thunk.AddressOfData > maxAddressOfData {
				maxAddressOfData = thunk.AddressOfData
			}

			if thunk.AddressOfData < minAddressOfData {
				minAddressOfData = thunk.AddressOfData
			}
		}

		thunkTable[rva] = &thunk
		thunkData := ThunkData64{ImageThunkData: thunk, Offset: rva}
		retVal = append(retVal, thunkData)
		rva += size
	}
	return retVal, nil
}

func (pe *File) parseImports32(importDesc interface{}, maxLen uint32) (
	[]ImportFunction, error) {

	var OriginalFirstThunk uint32
	var FirstThunk uint32
	var isOldDelayImport bool

	switch desc := importDesc.(type) {
	case *ImageImportDescriptor:
		OriginalFirstThunk = desc.OriginalFirstThunk
		FirstThunk = desc.FirstThunk
	case *ImageDelayImportDescriptor:
		OriginalFirstThunk = desc.ImportNameTableRVA
		FirstThunk = desc.ImportAddressTableRVA
		if desc.Attributes == 0 {
			isOldDelayImport = true
		}
	}

	// Import Lookup Table (OFT). Contains ordinals or pointers to strings.
	ilt, err := pe.getImportTable32(OriginalFirstThunk, maxLen, isOldDelayImport)
	if err != nil {
		return nil, err
	}

	// Import Address Table (FT). May have identical content to ILT if PE file is
	// not bound. It will contain the address of the imported symbols once
	// the binary is loaded or if it is already bound.
	iat, err := pe.getImportTable32(FirstThunk, maxLen, isOldDelayImport)
	if err != nil {
		return nil, err
	}

	// Some DLLs has IAT or ILT with nil type.
	if len(iat) == 0 && len(ilt) == 0 {
		return nil, ErrDamagedImportTable
	}

	var table []ThunkData32
	if len(ilt) > 0 {
		table = ilt
	} else if len(iat) > 0 {
		table = iat
	} else {
		return nil, err
	}

	importedFunctions := []ImportFunction{}
	numInvalid := uint32(0)
	for idx := uint32(0); idx < uint32(len(table)); idx++ {
		imp := ImportFunction{}
		if table[idx].ImageThunkData.AddressOfData > 0 {
			// If imported by ordinal, we will append the ordinal number
			if table[idx].ImageThunkData.AddressOfData&imageOrdinalFlag32 > 0 {
				imp.ByOrdinal = true
				imp.Ordinal = table[idx].ImageThunkData.AddressOfData & uint32(0xffff)

				// Original Thunk
				if uint32(len(ilt)) > idx {
					imp.OriginalThunkValue = uint64(ilt[idx].ImageThunkData.AddressOfData)
					imp.OriginalThunkRVA = ilt[idx].Offset
				}

				// Thunk
				if uint32(len(iat)) > idx {
					imp.ThunkValue = uint64(iat[idx].ImageThunkData.AddressOfData)
					imp.ThunkRVA = iat[idx].Offset
				}

				imp.Name = "#" + strconv.Itoa(int(imp.Ordinal))
			} else {
				imp.ByOrdinal = false
				if isOldDelayImport {
					table[idx].ImageThunkData.AddressOfData -=
						pe.NtHeader.OptionalHeader.(ImageOptionalHeader32).ImageBase
				}

				// Original Thunk
				if uint32(len(ilt)) > idx {
					imp.OriginalThunkValue = uint64(ilt[idx].ImageThunkData.AddressOfData & addressMask32)
					imp.OriginalThunkRVA = ilt[idx].Offset
				}

				// Thunk
				if uint32(len(iat)) > idx {
					imp.ThunkValue = uint64(iat[idx].ImageThunkData.AddressOfData & addressMask32)
					imp.ThunkRVA = iat[idx].Offset
				}

				// Thunk
				hintNameTableRva := table[idx].ImageThunkData.AddressOfData & addressMask32
				off := pe.GetOffsetFromRva(hintNameTableRva)
				imp.Hint, err = pe.ReadUint16(off)
				if err != nil {
					imp.Hint = ^uint16(0)
				}
				imp.Name = pe.getStringAtRVA(table[idx].ImageThunkData.AddressOfData+2,
					maxImportNameLength)
				if !IsValidFunctionName(imp.Name) {
					imp.Name = "*invalid*"
				}
			}
		}

		// This file bfe97192e8107d52dd7b4010d12b2924 has an invalid table built
		// in a way that it's parsable but contains invalid entries that lead
		// pefile to take extremely long amounts of time to parse. It also leads
		// to extreme memory consumption. To prevent similar cases, if invalid
		// entries are found in the middle of a table the parsing will be aborted.
		hasName := len(imp.Name) > 0
		if imp.Ordinal == 0 && !hasName {
			if !stringInSlice(AnoImportNoNameNoOrdinal, pe.Anomalies) {
				pe.Anomalies = append(pe.Anomalies, AnoImportNoNameNoOrdinal)
			}
		}

		// Some PEs appear to interleave valid and invalid imports. Instead of
		// aborting the parsing altogether we will simply skip the invalid entries.
		// Although if we see 1000 invalid entries and no legit ones, we abort.
		if imp.Name == "*invalid*" {
			if numInvalid > 1000 && numInvalid == idx {
				return nil, errors.New(
					`too many invalid names, aborting parsing`)
			}
			numInvalid++
			continue
		}

		importedFunctions = append(importedFunctions, imp)
	}

	return importedFunctions, nil
}

func (pe *File) parseImports64(importDesc interface{}, maxLen uint32) ([]ImportFunction, error) {

	var OriginalFirstThunk uint32
	var FirstThunk uint32
	var isOldDelayImport bool

	switch desc := importDesc.(type) {
	case *ImageImportDescriptor:
		OriginalFirstThunk = desc.OriginalFirstThunk
		FirstThunk = desc.FirstThunk
	case *ImageDelayImportDescriptor:
		OriginalFirstThunk = desc.ImportNameTableRVA
		FirstThunk = desc.ImportAddressTableRVA
		if desc.Attributes == 0 {
			isOldDelayImport = true
		}
	}

	// Import Lookup Table. Contains ordinals or pointers to strings.
	ilt, err := pe.getImportTable64(OriginalFirstThunk, maxLen, isOldDelayImport)
	if err != nil {
		return nil, err
	}

	// Import Address Table. May have identical content to ILT if PE file is
	// not bound. It will contain the address of the imported symbols once
	// the binary is loaded or if it is already bound.
	iat, err := pe.getImportTable64(FirstThunk, maxLen, isOldDelayImport)
	if err != nil {
		return nil, err
	}

	// Would crash if IAT or ILT had nil type
	if len(iat) == 0 && len(ilt) == 0 {
		return nil, ErrDamagedImportTable
	}

	var table []ThunkData64
	if len(ilt) > 0 {
		table = ilt
	} else if len(iat) > 0 {
		table = iat
	} else {
		return nil, err
	}

	importedFunctions := []ImportFunction{}
	numInvalid := uint32(0)
	for idx := uint32(0); idx < uint32(len(table)); idx++ {
		imp := ImportFunction{}
		if table[idx].ImageThunkData.AddressOfData > 0 {

			// If imported by ordinal, we will append the ordinal number
			if table[idx].ImageThunkData.AddressOfData&imageOrdinalFlag64 > 0 {
				imp.ByOrdinal = true
				imp.Ordinal = uint32(table[idx].ImageThunkData.AddressOfData) & uint32(0xffff)

				// Original Thunk
				if uint32(len(ilt)) > idx {
					imp.OriginalThunkValue =
						ilt[idx].ImageThunkData.AddressOfData
					imp.OriginalThunkRVA = ilt[idx].Offset
				}

				// Thunk
				if uint32(len(iat)) > idx {
					imp.ThunkValue = iat[idx].ImageThunkData.AddressOfData
					imp.ThunkRVA = iat[idx].Offset
				}

				imp.Name = "#" + strconv.Itoa(int(imp.Ordinal))

			} else {

				imp.ByOrdinal = false

				if isOldDelayImport {
					table[idx].ImageThunkData.AddressOfData -=
						pe.NtHeader.OptionalHeader.(ImageOptionalHeader64).ImageBase
				}

				// Original Thunk
				if uint32(len(ilt)) > idx {
					imp.OriginalThunkValue =
						ilt[idx].ImageThunkData.AddressOfData & addressMask64
					imp.OriginalThunkRVA = ilt[idx].Offset
				}

				// Thunk
				if uint32(len(iat)) > idx {
					imp.ThunkValue = iat[idx].ImageThunkData.AddressOfData & addressMask64
					imp.ThunkRVA = iat[idx].Offset
				}

				hintNameTableRva := table[idx].ImageThunkData.AddressOfData & addressMask64
				off := pe.GetOffsetFromRva(uint32(hintNameTableRva))
				imp.Hint = binary.LittleEndian.Uint16(pe.data[off:])
				imp.Name = pe.getStringAtRVA(uint32(table[idx].ImageThunkData.AddressOfData+2),
					maxImportNameLength)
				if !IsValidFunctionName(imp.Name) {
					imp.Name = "*invalid*"
				}
			}
		}

		// This file bfe97192e8107d52dd7b4010d12b2924 has an invalid table built
		// in a way that it's parsable but contains invalid entries that lead
		// pefile to take extremely long amounts of time to parse. It also leads
		// to extreme memory consumption. To prevent similar cases, if invalid
		// entries are found in the middle of a table the parsing will be aborted.
		hasName := len(imp.Name) > 0
		if imp.Ordinal == 0 && !hasName {
			if !stringInSlice(AnoImportNoNameNoOrdinal, pe.Anomalies) {
				pe.Anomalies = append(pe.Anomalies, AnoImportNoNameNoOrdinal)
			}
		}
		// Some PEs appear to interleave valid and invalid imports. Instead of
		// aborting the parsing altogether we will simply skip the invalid entries.
		// Although if we see 1000 invalid entries and no legit ones, we abort.
		if imp.Name == "*invalid*" {
			if numInvalid > 1000 && numInvalid == idx {
				return nil, errors.New(
					`too many invalid names, aborting parsing`)
			}
			numInvalid++
			continue
		}

		importedFunctions = append(importedFunctions, imp)
	}

	return importedFunctions, nil
}

// GetImportEntryInfoByRVA return an import function + index of the entry given
// an RVA.
func (pe *File) GetImportEntryInfoByRVA(rva uint32) (Import, int) {
	for _, imp := range pe.Imports {
		for i, entry := range imp.Functions {
			if entry.ThunkRVA == rva {
				return imp, i
			}
		}
	}

	return Import{}, 0
}

// md5hash hashes using md5 algorithm.
func md5hash(text string) string {
	h := md5.New()
	h.Write([]byte(text))
	return hex.EncodeToString(h.Sum(nil))
}

// ImpHash calculates the import hash.
// Algorithm:
// Resolving ordinals to function names when they appear
// Converting both DLL names and function names to all lowercase
// Removing the file extensions from imported module names
// Building and storing the lowercased string . in an ordered list
// Generating the MD5 hash of the ordered list
func (pe *File) ImpHash() (string, error) {
	if len(pe.Imports) == 0 {
		return "", errors.New("no imports found")
	}

	extensions := []string{"ocx", "sys", "dll"}
	var impStrs []string

	for _, imp := range pe.Imports {
		var libName string
		parts := strings.Split(imp.Name, ".")
		if len(parts) == 2 && stringInSlice(strings.ToLower(parts[1]), extensions) {
			libName = parts[0]
		} else {
			libName = imp.Name
		}

		libName = strings.ToLower(libName)

		for _, function := range imp.Functions {
			var funcName string
			if function.ByOrdinal {
				funcName = OrdLookup(imp.Name, uint64(function.Ordinal), true)
			} else {
				funcName = function.Name
			}

			if funcName == "" {
				continue
			}

			impStr := fmt.Sprintf("%s.%s", libName, strings.ToLower(funcName))
			impStrs = append(impStrs, impStr)
		}
	}

	hash := md5hash(strings.Join(impStrs, ","))
	return hash, nil
}
