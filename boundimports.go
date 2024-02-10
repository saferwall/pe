// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"encoding/binary"
)

const (
	// MaxStringLength represents the maximum length of a string to be retrieved
	// from the file. It's there to prevent loading massive amounts of data from
	// memory mapped files. Strings longer than 0x100B should be rather rare.
	MaxStringLength = uint32(0x100)
)

// ImageBoundImportDescriptor represents the IMAGE_BOUND_IMPORT_DESCRIPTOR.
type ImageBoundImportDescriptor struct {
	// TimeDateStamp is just the value from the Exports information of the DLL
	// which is being imported from.
	TimeDateStamp uint32 `json:"time_date_stamp"`
	// Offset of the DLL name counted from the beginning of the BOUND_IMPORT table.
	OffsetModuleName uint16 `json:"offset_module_name"`
	// Number of forwards,
	NumberOfModuleForwarderRefs uint16 `json:"number_of_module_forwarder_refs"`
	// Array of zero or more IMAGE_BOUND_FORWARDER_REF follows.
}

// ImageBoundForwardedRef represents the IMAGE_BOUND_FORWARDER_REF.
type ImageBoundForwardedRef struct {
	TimeDateStamp    uint32 `json:"time_date_stamp"`
	OffsetModuleName uint16 `json:"offset_module_name"`
	Reserved         uint16 `json:"reserved"`
}

// BoundImportDescriptorData represents the descriptor in addition to forwarded refs.
type BoundImportDescriptorData struct {
	Struct        ImageBoundImportDescriptor `json:"struct"`
	Name          string                     `json:"name"`
	ForwardedRefs []BoundForwardedRefData    `json:"forwarded_refs"`
}

// BoundForwardedRefData represents the struct in addition to the dll name.
type BoundForwardedRefData struct {
	Struct ImageBoundForwardedRef `json:"struct"`
	Name   string                 `json:"name"`
}

// This table is an array of bound import descriptors, each of which describes
// a DLL this image was bound up with at the time of the image creation.
// The descriptors also carry the time stamps of the bindings, and if the
// bindings are up-to-date, the OS loader uses these bindings as a “shortcut”
// for API import. Otherwise, the loader ignores the bindings and resolves the
// imported APIs through the Import tables.
func (pe *File) parseBoundImportDirectory(rva, size uint32) (err error) {
	var sectionsAfterOffset []uint32
	var safetyBoundary uint32
	var start = rva

	for {
		bndDesc := ImageBoundImportDescriptor{}
		bndDescSize := uint32(binary.Size(bndDesc))
		err = pe.structUnpack(&bndDesc, rva, bndDescSize)
		// If the RVA is invalid all would blow up. Some EXEs seem to be
		// specially nasty and have an invalid RVA.
		if err != nil {
			return err
		}

		// If the structure is all zeros, we reached the end of the list.
		if bndDesc == (ImageBoundImportDescriptor{}) {
			break
		}

		rva += bndDescSize
		sectionsAfterOffset = nil

		fileOffset := pe.GetOffsetFromRva(rva)
		section := pe.getSectionByRva(rva)
		if section == nil {
			safetyBoundary = pe.size - fileOffset
			for _, section := range pe.Sections {
				if section.Header.PointerToRawData > fileOffset {
					sectionsAfterOffset = append(
						sectionsAfterOffset, section.Header.PointerToRawData)
				}
			}
			if len(sectionsAfterOffset) > 0 {
				// Find the first section starting at a later offset than that
				// specified by 'rva'
				firstSectionAfterOffset := Min(sectionsAfterOffset)
				section = pe.getSectionByOffset(firstSectionAfterOffset)
				if section != nil {
					safetyBoundary = section.Header.PointerToRawData - fileOffset
				}
			}
		} else {
			sectionLen := uint32(len(section.Data(0, 0, pe)))
			safetyBoundary = (section.Header.PointerToRawData + sectionLen) - fileOffset
		}

		if section == nil {
			pe.logger.Warnf("RVA of IMAGE_BOUND_IMPORT_DESCRIPTOR points to an invalid address: 0x%x", rva)
			return nil
		}

		bndFrwdRef := ImageBoundForwardedRef{}
		bndFrwdRefSize := uint32(binary.Size(bndFrwdRef))
		count := min(uint32(bndDesc.NumberOfModuleForwarderRefs), safetyBoundary/bndFrwdRefSize)

		forwarderRefs := make([]BoundForwardedRefData, 0)
		for i := uint32(0); i < count; i++ {
			err = pe.structUnpack(&bndFrwdRef, rva, bndFrwdRefSize)
			if err != nil {
				return err
			}

			rva += bndFrwdRefSize

			offset := start + uint32(bndFrwdRef.OffsetModuleName)
			DllNameBuff := string(pe.GetStringFromData(0, pe.data[offset:offset+MaxStringLength]))
			DllName := string(DllNameBuff)

			// OffsetModuleName points to a DLL name. These shouldn't be too long.
			// Anything longer than a safety length of 128 will be taken to indicate
			// a corrupt entry and abort the processing of these entries.
			// Names shorter than 4 characters will be taken as invalid as well.
			if DllName != "" && (len(DllName) > 256 || !IsPrintable(DllName)) {
				break
			}

			forwarderRefs = append(forwarderRefs, BoundForwardedRefData{
				Struct: bndFrwdRef, Name: DllName})
		}

		offset := start + uint32(bndDesc.OffsetModuleName)
		DllNameBuff := pe.GetStringFromData(0, pe.data[offset:offset+MaxStringLength])
		DllName := string(DllNameBuff)
		if DllName != "" && (len(DllName) > 256 || !IsPrintable(DllName)) {
			break
		}

		pe.BoundImports = append(pe.BoundImports, BoundImportDescriptorData{
			Struct:        bndDesc,
			Name:          DllName,
			ForwardedRefs: forwarderRefs})
	}

	if len(pe.BoundImports) > 0 {
		pe.HasBoundImp = true
	}
	return nil
}
