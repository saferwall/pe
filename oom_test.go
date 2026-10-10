// Copyright 2026 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"encoding/binary"
	"io/ioutil"
	"testing"
)

func getTestDataDirectory(peFile *File, entry ImageDirectoryEntry) DataDirectory {
	if peFile.Is64 {
		return peFile.NtHeader.OptionalHeader.(ImageOptionalHeader64).DataDirectory[entry]
	}
	return peFile.NtHeader.OptionalHeader.(ImageOptionalHeader32).DataDirectory[entry]
}

func getDataDirectoryOffset(peFile *File, entry ImageDirectoryEntry) uint32 {
	ohOffset := peFile.DOSHeader.AddressOfNewEXEHeader + 4 + uint32(binary.Size(peFile.NtHeader.FileHeader))
	if peFile.Is64 {
		return ohOffset + 112 + (uint32(entry) * 8)
	}
	return ohOffset + 96 + (uint32(entry) * 8)
}

// TestIssue138DebugDirectoryOOM verifies that corrupt or unconstrained SizeOfData
// values in CodeView debug directories (RSDS and NB10) do not trigger out-of-memory
// panics from unsigned integer underflow or massive slice allocation.
func TestIssue138DebugDirectoryOOM(t *testing.T) {
	filePath := getAbsoluteFilePath("test/kernel32.dll")
	baseData, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read test file %s: %v", filePath, err)
	}

	testSizes := []uint32{
		0,          // Triggers 0 - 25 underflow to 0xffffffe7 (exact issue #138 reproducer)
		1,          // Underflow
		10,         // Underflow
		24,         // Underflow
		25,         // Boundary condition: exactly 24 + 1
		0x7fffffff, // Over 2GB: exceeds file size
		0xffffffff, // Maximum uint32: exceeds file size
	}

	for _, badSize := range testSizes {
		data := make([]byte, len(baseData))
		copy(data, baseData)

		peFile, err := NewBytes(data, &Options{})
		if err != nil {
			t.Fatalf("NewBytes failed: %v", err)
		}

		err = peFile.Parse()
		if err != nil {
			t.Fatalf("initial Parse failed: %v", err)
		}

		if len(peFile.Debugs) == 0 {
			t.Fatalf("expected at least one debug directory entry in kernel32.dll")
		}

		debugRVA := getTestDataDirectory(peFile, ImageDirectoryEntryDebug).VirtualAddress
		debugDirOffset := peFile.GetOffsetFromRva(debugRVA)
		if debugDirOffset >= peFile.size-28 {
			t.Fatalf("invalid debug directory offset: %d", debugDirOffset)
		}

		// Overwrite SizeOfData at offset + 16
		binary.LittleEndian.PutUint32(data[debugDirOffset+16:], badSize)

		reparsedFile, err := NewBytes(data, &Options{})
		if err != nil {
			t.Fatalf("NewBytes failed for size 0x%x: %v", badSize, err)
		}

		// Parse must complete gracefully without OOM panic
		_ = reparsedFile.Parse()
	}
}

// TestDebugDirectoryNB10OOM verifies that CodeView NB10 debug entries with
// corrupt SizeOfData values do not trigger underflow or OOM panics.
func TestDebugDirectoryNB10OOM(t *testing.T) {
	filePath := getAbsoluteFilePath("test/kernel32.dll")
	baseData, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read test file %s: %v", filePath, err)
	}

	testSizes := []uint32{
		0,          // Triggers 0 - 17 underflow to 0xffffffef
		5,          // Underflow
		16,         // Underflow
		17,         // Boundary condition: exactly 16 + 1
		0x80000000, // Exceeds file size
		0xffffffff, // Maximum uint32
	}

	for _, badSize := range testSizes {
		data := make([]byte, len(baseData))
		copy(data, baseData)

		peFile, err := NewBytes(data, &Options{})
		if err != nil {
			t.Fatalf("NewBytes failed: %v", err)
		}

		err = peFile.Parse()
		if err != nil {
			t.Fatalf("initial Parse failed: %v", err)
		}

		debugRVA := getTestDataDirectory(peFile, ImageDirectoryEntryDebug).VirtualAddress
		debugDirOffset := peFile.GetOffsetFromRva(debugRVA)
		rawPointer := binary.LittleEndian.Uint32(data[debugDirOffset+24:])
		if rawPointer < uint32(len(data))-4 {
			// Change CodeView signature from RSDS to NB10
			binary.LittleEndian.PutUint32(data[rawPointer:], CVSignatureNB10)
		}

		// Overwrite SizeOfData at offset + 16
		binary.LittleEndian.PutUint32(data[debugDirOffset+16:], badSize)

		reparsedFile, err := NewBytes(data, &Options{})
		if err != nil {
			t.Fatalf("NewBytes failed for NB10 size 0x%x: %v", badSize, err)
		}

		_ = reparsedFile.Parse()
	}
}

// TestDebugDirectoryExtremeDirectoryCount verifies that an extreme size field
// in the debug data directory does not trigger unbounded loop or memory allocations.
func TestDebugDirectoryExtremeDirectoryCount(t *testing.T) {
	filePath := getAbsoluteFilePath("test/kernel32.dll")
	baseData, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read test file %s: %v", filePath, err)
	}

	data := make([]byte, len(baseData))
	copy(data, baseData)

	peFile, err := NewBytes(data, &Options{})
	if err != nil {
		t.Fatalf("NewBytes failed: %v", err)
	}
	err = peFile.Parse()
	if err != nil {
		t.Fatalf("initial Parse failed: %v", err)
	}

	debugDirEntryOffset := getDataDirectoryOffset(peFile, ImageDirectoryEntryDebug)

	// Set debug directory size to 0xFFFFFFFF
	binary.LittleEndian.PutUint32(data[debugDirEntryOffset+4:], 0xffffffff)

	reparsedFile, err := NewBytes(data, &Options{})
	if err != nil {
		t.Fatalf("NewBytes failed: %v", err)
	}

	_ = reparsedFile.Parse()
}

// TestOverlayBounds verifies that Overlay returns ErrNoOverlayFound when
// OverlayOffset exceeds or matches the file size, avoiding negative slice allocations.
func TestOverlayBounds(t *testing.T) {
	filePath := getAbsoluteFilePath("test/putty.exe")
	peFile, err := New(filePath, &Options{})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	err = peFile.Parse()
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	// Set OverlayOffset past file end
	peFile.OverlayOffset = int64(peFile.size) + 1000
	_, err = peFile.Overlay()
	if err != ErrNoOverlayFound {
		t.Errorf("expected ErrNoOverlayFound, got %v", err)
	}
	if peFile.OverlayLength() != 0 {
		t.Errorf("expected OverlayLength 0, got %d", peFile.OverlayLength())
	}

	// Set negative OverlayOffset
	peFile.OverlayOffset = -50
	_, err = peFile.Overlay()
	if err != ErrNoOverlayFound {
		t.Errorf("expected ErrNoOverlayFound for negative offset, got %v", err)
	}
	if peFile.OverlayLength() != 0 {
		t.Errorf("expected OverlayLength 0 for negative offset, got %d", peFile.OverlayLength())
	}
}

// TestExportDirectoryExtremeCounts verifies that corrupted export header counts
// do not cause massive allocations or out-of-bounds slice indexing.
func TestExportDirectoryExtremeCounts(t *testing.T) {
	filePath := getAbsoluteFilePath("test/kernel32.dll")
	baseData, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read test file %s: %v", filePath, err)
	}

	data := make([]byte, len(baseData))
	copy(data, baseData)

	peFile, err := NewBytes(data, &Options{})
	if err != nil {
		t.Fatalf("NewBytes failed: %v", err)
	}
	err = peFile.Parse()
	if err != nil {
		t.Fatalf("initial Parse failed: %v", err)
	}

	exportRVA := getTestDataDirectory(peFile, ImageDirectoryEntryExport).VirtualAddress
	exportOffset := peFile.GetOffsetFromRva(exportRVA)

	// NumberOfFunctions at offset + 20, NumberOfNames at offset + 24
	binary.LittleEndian.PutUint32(data[exportOffset+20:], 0xffffffff)
	binary.LittleEndian.PutUint32(data[exportOffset+24:], 0xffffffff)

	reparsedFile, err := NewBytes(data, &Options{})
	if err != nil {
		t.Fatalf("NewBytes failed: %v", err)
	}

	_ = reparsedFile.Parse()
}

// TestCOFFSymbolsExtremeCount verifies that a huge NumberOfSymbols in COFF header
// is clamped to avoid excessive slice allocations.
func TestCOFFSymbolsExtremeCount(t *testing.T) {
	filePath := getAbsoluteFilePath("test/putty.exe")
	baseData, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read test file %s: %v", filePath, err)
	}

	data := make([]byte, len(baseData))
	copy(data, baseData)

	peFile, err := NewBytes(data, &Options{})
	if err != nil {
		t.Fatalf("NewBytes failed: %v", err)
	}
	err = peFile.Parse()
	if err != nil {
		t.Fatalf("initial Parse failed: %v", err)
	}

	coffOffset := peFile.DOSHeader.AddressOfNewEXEHeader + 4
	// PointerToSymbolTable at offset + 8, NumberOfSymbols at offset + 12
	binary.LittleEndian.PutUint32(data[coffOffset+8:], 0x200)
	binary.LittleEndian.PutUint32(data[coffOffset+12:], 0xffffffff)

	reparsedFile, err := NewBytes(data, &Options{})
	if err != nil {
		t.Fatalf("NewBytes failed: %v", err)
	}

	_ = reparsedFile.Parse()
}

// TestExceptionDirectoryExtremeSize verifies that an extreme size field in the
// Exception data directory is clamped to avoid excessive allocations.
func TestExceptionDirectoryExtremeSize(t *testing.T) {
	filePath := getAbsoluteFilePath("test/putty.exe")
	baseData, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read test file %s: %v", filePath, err)
	}

	data := make([]byte, len(baseData))
	copy(data, baseData)

	peFile, err := NewBytes(data, &Options{})
	if err != nil {
		t.Fatalf("NewBytes failed: %v", err)
	}
	err = peFile.Parse()
	if err != nil {
		t.Fatalf("initial Parse failed: %v", err)
	}

	excDirEntryOffset := getDataDirectoryOffset(peFile, ImageDirectoryEntryException)

	// Set Exception directory size to 0xFFFFFFFF
	binary.LittleEndian.PutUint32(data[excDirEntryOffset+4:], 0xffffffff)

	reparsedFile, err := NewBytes(data, &Options{})
	if err != nil {
		t.Fatalf("NewBytes failed: %v", err)
	}

	_ = reparsedFile.Parse()
}

// TestLoadConfigExtremeCounts verifies that corrupted load configuration table
// counts do not trigger runaway loops or excessive slice allocations.
func TestLoadConfigExtremeCounts(t *testing.T) {
	filePath := getAbsoluteFilePath("test/putty.exe")
	baseData, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read test file %s: %v", filePath, err)
	}

	data := make([]byte, len(baseData))
	copy(data, baseData)

	peFile, err := NewBytes(data, &Options{})
	if err != nil {
		t.Fatalf("NewBytes failed: %v", err)
	}
	err = peFile.Parse()
	if err != nil {
		t.Fatalf("initial Parse failed: %v", err)
	}

	lcDirEntryOffset := getDataDirectoryOffset(peFile, ImageDirectoryEntryLoadConfig)

	// Set LoadConfig directory size to 0xFFFFFFFF
	binary.LittleEndian.PutUint32(data[lcDirEntryOffset+4:], 0xffffffff)

	reparsedFile, err := NewBytes(data, &Options{})
	if err != nil {
		t.Fatalf("NewBytes failed: %v", err)
	}

	_ = reparsedFile.Parse()
}

// TestBoundImportsExtremeCounts verifies that corrupted bound import forwarder
// counts do not trigger excessive allocations or out-of-bounds slicing.
func TestBoundImportsExtremeCounts(t *testing.T) {
	filePath := getAbsoluteFilePath("test/putty.exe")
	baseData, err := ioutil.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read test file %s: %v", filePath, err)
	}

	data := make([]byte, len(baseData))
	copy(data, baseData)

	peFile, err := NewBytes(data, &Options{})
	if err != nil {
		t.Fatalf("NewBytes failed: %v", err)
	}
	err = peFile.Parse()
	if err != nil {
		t.Fatalf("initial Parse failed: %v", err)
	}

	biDirEntryOffset := getDataDirectoryOffset(peFile, ImageDirectoryEntryBoundImport)

	// Set BoundImport directory size to 0xFFFFFFFF
	binary.LittleEndian.PutUint32(data[biDirEntryOffset+4:], 0xffffffff)

	reparsedFile, err := NewBytes(data, &Options{})
	if err != nil {
		t.Fatalf("NewBytes failed: %v", err)
	}

	_ = reparsedFile.Parse()
}
