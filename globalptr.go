// Copyright 2022 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

const (
	// AnoInvalidGlobalPtrReg is reported when the global pointer register offset is outide the image.
	AnoInvalidGlobalPtrReg = "Global pointer register offset outside of PE image"
)

// RVA of the value to be stored in the global pointer register. The size must
// be set to 0. This data directory is set to all zeros if the target
// architecture (for example, I386 or AMD64) does not use the concept of a
// global pointer.
func (pe *File) parseGlobalPtrDirectory(rva, size uint32) error {

	var err error

	// RVA of the value to be stored in the global pointer register.
	offset := pe.GetOffsetFromRva(rva)
	if offset == ^uint32(0) {
		// Fake global pointer data directory
		// sample: 0101f36de484fbc7bfbe6cb942a1ecf6fac0c3acd9f65b88b19400582d7e7007
		pe.Anomalies = append(pe.Anomalies, AnoInvalidGlobalPtrReg)
		return nil
	}

	pe.GlobalPtr, err = pe.ReadUint32(offset)
	if err != nil {
		return err
	}

	pe.HasGlobalPtr = true
	return nil
}
