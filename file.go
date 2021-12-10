// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"errors"
	"fmt"
	"os"

	mmap "github.com/edsrzf/mmap-go"
)

// A File represents an open PE file.
type File struct {
	DosHeader    ImageDosHeader              `json:",omitempty"`
	RichHeader   *RichHeader                 `json:",omitempty"`
	NtHeader     ImageNtHeader               `json:",omitempty"`
	COFF         *COFF                       `json:",omitempty"`
	Sections     []Section                   `json:",omitempty"`
	Imports      []Import                    `json:",omitempty"`
	Export       *Export                     `json:",omitempty"`
	Debugs       []DebugEntry                `json:",omitempty"`
	Relocations  []Relocation                `json:",omitempty"`
	Resources    *ResourceDirectory          `json:",omitempty"`
	TLS          *TLSDirectory               `json:",omitempty"`
	LoadConfig   *LoadConfig                 `json:",omitempty"`
	Exceptions   []Exception                 `json:",omitempty"`
	Certificates *Certificate                `json:",omitempty"`
	DelayImports []DelayImport               `json:",omitempty"`
	BoundImports []BoundImportDescriptorData `json:",omitempty"`
	GlobalPtr    uint32                      `json:",omitempty"`
	CLR          *CLRData                    `json:",omitempty"`
	IAT          []IATEntry                  `json:",omitempty"`
	Header       []byte
	data         mmap.MMap
	Is64         bool
	Is32         bool
	Anomalies    []string `json:",omitempty"`
	size         uint32
	f            *os.File
	opts         *Options
}

// Options for Parsing
type Options struct {

	// Parse only the PE header.
	// do not parse data directories, by default (false).
	Fast bool

	// Includes section entropy.
	SectionEntropy bool

	// Maximum COFF symbols to parse.
	MaxCOFFSymbolsCount uint64
}

// New instaniates a file instance with options given a file name.
func New(name string, opts *Options) (*File, error) {

	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	// Memory map the file insead of using read/write.
	data, err := mmap.Map(f, mmap.RDONLY, 0)
	if err != nil {
		f.Close()
		return nil, err
	}

	file := File{}
	if opts != nil {
		file.opts = opts
	} else {
		file.opts = &Options{}
	}

	if file.opts.MaxCOFFSymbolsCount == 0 {
		file.opts.MaxCOFFSymbolsCount = MaxDefaultCOFFSymbolsCount
	}

	file.data = data
	file.size = uint32(len(file.data))
	file.f = f
	return &file, nil
}

// NewBytes instaniates a file instance with options given a memory buffer.
func NewBytes(data []byte, opts *Options) (*File, error) {

	file := File{}
	if opts != nil {
		file.opts = opts
	} else {
		file.opts = &Options{}
	}
	file.data = data
	file.size = uint32(len(file.data))
	return &file, nil
}

// Close closes the File.
func (pe *File) Close() error {
	if pe.f != nil {
		return pe.f.Close()
	}
	return nil
}

// Parse performs the file parsing for a PE binary.
func (pe *File) Parse() error {

	// check for the smallest PE size.
	if len(pe.data) < TinyPESize {
		return ErrInvalidPESize
	}

	// Parse the DOS header.
	err := pe.ParseDOSHeader()
	if err != nil {
		return err
	}

	// Parse the Rich header.
	err = pe.ParseRichHeader()
	if err != nil {
		return err
	}

	// Parse the NT header.
	err = pe.ParseNTHeader()
	if err != nil {
		return err
	}

	// Parse COFF symbol table.
	pe.ParseCOFFSymbolTable()

	// Parse the Section Header.
	err = pe.ParseSectionHeader()
	if err != nil {
		return err
	}

	// In fast mode, do not parse data directories.
	if pe.opts.Fast {
		return nil
	}

	// Parse the Data Directory entries.
	err = pe.ParseDataDirectories()
	return err
}

// PrettyDataDirectory returns the string representations
// of the data directory entry.
func (pe *File) PrettyDataDirectory(entry int) string {
	dataDirMap := map[int]string{
		ImageDirectoryEntryExport:       "Export",
		ImageDirectoryEntryImport:       "Import",
		ImageDirectoryEntryResource:     "Resource",
		ImageDirectoryEntryException:    "Exception",
		ImageDirectoryEntryCertificate:  "Security",
		ImageDirectoryEntryBaseReloc:    "Relocation",
		ImageDirectoryEntryDebug:        "Debug",
		ImageDirectoryEntryArchitecture: "Architecture",
		ImageDirectoryEntryGlobalPtr:    "GlobalPtr",
		ImageDirectoryEntryTLS:          "TLS",
		ImageDirectoryEntryLoadConfig:   "LoadConfig",
		ImageDirectoryEntryBoundImport:  "BoundImport",
		ImageDirectoryEntryIAT:          "IAT",
		ImageDirectoryEntryDelayImport:  "DelayImport",
		ImageDirectoryEntryCLR:          "CLR",
	}

	return dataDirMap[entry]
}

// ParseDataDirectories parses the data directores. The DataDirectory is an
// array of 16 structures. Each array entry has a predefined meaning for what
// it refers to.
func (pe *File) ParseDataDirectories() error {

	foundErr := false
	oh32 := ImageOptionalHeader32{}
	oh64 := ImageOptionalHeader64{}

	switch pe.Is64 {
	case true:
		oh64 = pe.NtHeader.OptionalHeader.(ImageOptionalHeader64)
	case false:
		oh32 = pe.NtHeader.OptionalHeader.(ImageOptionalHeader32)
	}

	// Maps data directory index to function which parses that directory.
	funcMaps := map[int](func(uint32, uint32) error){
		ImageDirectoryEntryExport:       pe.parseExportDirectory,
		ImageDirectoryEntryImport:       pe.parseImportDirectory,
		ImageDirectoryEntryResource:     pe.parseResourceDirectory,
		ImageDirectoryEntryException:    pe.parseExceptionDirectory,
		ImageDirectoryEntryCertificate:  pe.parseSecurityDirectory,
		ImageDirectoryEntryBaseReloc:    pe.parseRelocDirectory,
		ImageDirectoryEntryDebug:        pe.parseDebugDirectory,
		ImageDirectoryEntryArchitecture: pe.parseArchitectureDirectory,
		ImageDirectoryEntryGlobalPtr:    pe.parseGlobalPtrDirectory,
		ImageDirectoryEntryTLS:          pe.parseTLSDirectory,
		ImageDirectoryEntryLoadConfig:   pe.parseLoadConfigDirectory,
		ImageDirectoryEntryBoundImport:  pe.parseBoundImportDirectory,
		ImageDirectoryEntryIAT:          pe.parseIATDirectory,
		ImageDirectoryEntryDelayImport:  pe.parseDelayImportDirectory,
		ImageDirectoryEntryCLR:          pe.parseCLRHeaderDirectory,
	}

	// Iterate over data directories and call the appropriate function.
	for entryIndex := 0; entryIndex < ImageNumberOfDirectoryEntries; entryIndex++ {

		var va, size uint32
		switch pe.Is64 {
		case true:
			dirEntry := oh64.DataDirectory[entryIndex]
			va = dirEntry.VirtualAddress
			size = dirEntry.Size
		case false:
			dirEntry := oh32.DataDirectory[entryIndex]
			va = dirEntry.VirtualAddress
			size = dirEntry.Size
		}

		if va != 0 {
			func() {
				//  keep parsing data directories even though some entries fails.
				defer func() {
					if e := recover(); e != nil {
						fmt.Printf("Unhandled Exception when trying to parse data directory %s, reason: %v\n",
							pe.PrettyDataDirectory(entryIndex), e)
						foundErr = true
					}
				}()

				err := funcMaps[entryIndex](va, size)
				if err != nil {
					fmt.Printf("Failed to parse data directory %s, reason: %v\n",
						pe.PrettyDataDirectory(entryIndex), err)
					foundErr = true
				}
			}()
		}
	}

	if foundErr {
		return errors.New("Data directory parsing failed")
	}
	return nil
}
