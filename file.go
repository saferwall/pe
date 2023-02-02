// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package pe

import (
	"errors"
	"os"

	mmap "github.com/edsrzf/mmap-go"
	"github.com/saferwall/pe/log"
)

// A File represents an open PE file.
type File struct {
	DOSHeader    ImageDOSHeader              `json:"dos_header,omitempty"`
	RichHeader   RichHeader                  `json:"rich_header,omitempty"`
	NtHeader     ImageNtHeader               `json:"nt_header,omitempty"`
	COFF         COFF                        `json:"coff,omitempty"`
	Sections     []Section                   `json:"sections,omitempty"`
	Imports      []Import                    `json:"imports,omitempty"`
	Export       Export                      `json:"export,omitempty"`
	Debugs       []DebugEntry                `json:"debugs,omitempty"`
	Relocations  []Relocation                `json:"relocations,omitempty"`
	Resources    ResourceDirectory           `json:"resources,omitempty"`
	TLS          TLSDirectory                `json:"tls,omitempty"`
	LoadConfig   LoadConfig                  `json:"load_config,omitempty"`
	Exceptions   []Exception                 `json:"exceptions,omitempty"`
	Certificates Certificate                 `json:"certificates,omitempty"`
	DelayImports []DelayImport               `json:"delay_imports,omitempty"`
	BoundImports []BoundImportDescriptorData `json:"bound_imports,omitempty"`
	GlobalPtr    uint32                      `json:"global_ptr,omitempty"`
	CLR          CLRData                     `json:"clr,omitempty"`
	IAT          []IATEntry                  `json:"iat,omitempty"`
	Anomalies    []string                    `json:"anomalies,omitempty"`
	Header       []byte
	data         mmap.MMap
	FileInfo
	size          uint32
	OverlayOffset int64
	f             *os.File
	opts          *Options
	logger        *log.Helper
}

// Options for Parsing
type Options struct {

	// Parse only the PE header and do not parse data directories, by default (false).
	Fast bool

	// Includes section entropy, by default (false).
	SectionEntropy bool

	// Maximum COFF symbols to parse, by default (MaxDefaultCOFFSymbolsCount).
	MaxCOFFSymbolsCount uint32

	// Maximum relocations to parse, by default (MaxDefaultRelocEntriesCount).
	MaxRelocEntriesCount uint32

	// Disable certificate validation, by default (false).
	DisableCertValidation bool

	// A custom logger.
	Logger log.Logger
}

// New instantiates a file instance with options given a file name.
func New(name string, opts *Options) (*File, error) {

	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	// Memory map the file instead of using read/write.
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
	if file.opts.MaxRelocEntriesCount == 0 {
		file.opts.MaxRelocEntriesCount = MaxDefaultRelocEntriesCount
	}

	var logger log.Logger
	if opts.Logger == nil {
		logger = log.NewStdLogger(os.Stdout)
		file.logger = log.NewHelper(log.NewFilter(logger,
			log.FilterLevel(log.LevelError)))
	} else {
		file.logger = log.NewHelper(opts.Logger)
	}

	file.data = data
	file.size = uint32(len(file.data))
	file.f = f
	return &file, nil
}

// NewBytes instantiates a file instance with options given a memory buffer.
func NewBytes(data []byte, opts *Options) (*File, error) {

	file := File{}
	if opts != nil {
		file.opts = opts
	} else {
		file.opts = &Options{}
	}

	if file.opts.MaxCOFFSymbolsCount == 0 {
		file.opts.MaxCOFFSymbolsCount = MaxDefaultCOFFSymbolsCount
	}
	if file.opts.MaxRelocEntriesCount == 0 {
		file.opts.MaxRelocEntriesCount = MaxDefaultRelocEntriesCount
	}

	var logger log.Logger
	if opts.Logger == nil {
		logger = log.NewStdLogger(os.Stdout)
		file.logger = log.NewHelper(log.NewFilter(logger,
			log.FilterLevel(log.LevelError)))
	} else {
		file.logger = log.NewHelper(opts.Logger)
	}

	file.data = data
	file.size = uint32(len(file.data))
	return &file, nil
}

// Close closes the File.
func (pe *File) Close() error {
	if pe.data != nil {
		_ = pe.data.Unmap()
	}

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
		pe.logger.Errorf("rich header parsing failed: %v", err)
	}

	// Parse the NT header.
	err = pe.ParseNTHeader()
	if err != nil {
		return err
	}

	// Parse COFF symbol table.
	err = pe.ParseCOFFSymbolTable()
	if err != nil {
		pe.logger.Debugf("coff symbols parsing failed: %v", err)
	}

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
	return pe.ParseDataDirectories()
}

// String stringify the data directory entry.
func (entry ImageDirectoryEntry) String() string {
	dataDirMap := map[ImageDirectoryEntry]string{
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
		ImageDirectoryEntryReserved:     "Reserved",
	}

	return dataDirMap[entry]
}

// ParseDataDirectories parses the data directories. The DataDirectory is an
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
	funcMaps := map[ImageDirectoryEntry](func(uint32, uint32) error){
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
	for entryIndex := ImageDirectoryEntry(0); entryIndex < ImageNumberOfDirectoryEntries; entryIndex++ {

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
				// keep parsing data directories even though some entries fails.
				defer func() {
					if e := recover(); e != nil {
						pe.logger.Errorf("unhandled exception when parsing data directory %s, reason: %v",
							entryIndex.String(), e)
						foundErr = true
					}
				}()

				// the last entry in the data directories is reserved and must be zero.
				if entryIndex == ImageDirectoryEntryReserved {
					pe.Anomalies = append(pe.Anomalies, AnoReservedDataDirectoryEntry)
					return
				}

				err := funcMaps[entryIndex](va, size)
				if err != nil {
					pe.logger.Warnf("failed to parse data directory %s, reason: %v",
						entryIndex.String(), err)
				}
			}()
		}
	}

	if foundErr {
		return errors.New("Data directory parsing failed")
	}
	return nil
}
