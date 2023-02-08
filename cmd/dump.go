// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"
	"unsafe"

	peparser "github.com/saferwall/pe"
	"github.com/saferwall/pe/log"
)

func prettyPrint(buff []byte) string {
	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, buff, "", "\t")
	if error != nil {
		log.Info("JSON parse error: ", error)
		return string(buff)
	}

	return prettyJSON.String()
}

func hexDump(b []byte) {
	var a [16]byte
	n := (len(b) + 15) &^ 15
	for i := 0; i < n; i++ {
		if i%16 == 0 {
			fmt.Printf("%4d", i)
		}
		if i%8 == 0 {
			fmt.Print(" ")
		}
		if i < len(b) {
			fmt.Printf(" %02X", b[i])
		} else {
			fmt.Print("   ")
		}
		if i >= len(b) {
			a[i%16] = ' '
		} else if b[i] < 32 || b[i] > 126 {
			a[i%16] = '.'
		} else {
			a[i%16] = b[i]
		}
		if i%16 == 15 {
			fmt.Printf("  %s\n", string(a[:]))
		}
	}
}

func hexDumpSize(b []byte, size int) {
	var a [16]byte
	n := (size + 15) &^ 15
	for i := 0; i < n; i++ {
		if i%16 == 0 {
			fmt.Printf("%4d", i)
		}
		if i%8 == 0 {
			fmt.Print(" ")
		}
		if i < len(b) {
			fmt.Printf(" %02X", b[i])
		} else {
			fmt.Print("   ")
		}
		if i >= len(b) {
			a[i%16] = ' '
		} else if b[i] < 32 || b[i] > 126 {
			a[i%16] = '.'
		} else {
			a[i%16] = b[i]
		}
		if i%16 == 15 {
			fmt.Printf("  %s\n", string(a[:]))
		}
	}
}

func IntToByteArray(num uint64) []byte {
	size := int(unsafe.Sizeof(num))
	arr := make([]byte, size)
	for i := 0; i < size; i++ {
		byt := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&num)) + uintptr(i)))
		arr[i] = byt
	}
	return arr
}

func isDirectory(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fileInfo.IsDir()
}

func parse(filePath string, cfg config) {

	// filePath points to a file.
	if !isDirectory(filePath) {
		parsePE(filePath, cfg)

	} else {
		// filePath points to a directory,
		// walk recursively through all files.
		fileList := []string{}
		filepath.Walk(filePath, func(path string, f os.FileInfo, err error) error {
			if !isDirectory(path) {
				fileList = append(fileList, path)
			}
			return nil
		})

		for _, file := range fileList {
			parsePE(file, cfg)
		}
	}
}

func parsePE(filename string, cfg config) {

	logger := log.NewStdLogger(os.Stdout)
	logger = log.NewFilter(logger, log.FilterLevel(log.LevelInfo))
	log := log.NewHelper(logger)

	log.Infof("parsing filename %s", filename)

	data, _ := os.ReadFile(filename)
	pe, err := peparser.NewBytes(data, &peparser.Options{
		Logger: logger,
	})

	if err != nil {
		log.Infof("Error while opening file: %s, reason: %s", filename, err)
		return
	}
	defer pe.Close()

	err = pe.Parse()
	if err != nil {
		if err != peparser.ErrDOSMagicNotFound {
			log.Infof("Error while parsing file: %s, reason: %s", filename, err)
		}
		return
	}

	// Dump all results to disk in JSON format.
	b, _ := json.Marshal(pe)
	f, err := os.Create("out.json")
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(prettyPrint(b))

	// Calculate the PE authentihash.
	pe.Authentihash()

	// Calculate the PE checksum.
	pe.Checksum()

	// Get file type.
	if pe.IsEXE() {
		log.Debug("File is Exe")
	}
	if pe.IsDLL() {
		log.Debug("File is DLL")
	}
	if pe.IsDriver() {
		log.Debug("File is Driver")
	}

	if cfg.wantDOSHeader {
		DOSHeader := pe.DOSHeader
		magic := string(IntToByteArray(uint64(DOSHeader.Magic)))
		signature := string(IntToByteArray(uint64(pe.NtHeader.Signature)))
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 3, ' ', tabwriter.AlignRight)
		fmt.Print("\n---DOS Header ---\n\n")
		fmt.Fprintf(w, "Magic:\t 0x%x (%s)\n", DOSHeader.Magic, magic)
		fmt.Fprintf(w, "Bytes On Last Page Of File:\t 0x%x\n", DOSHeader.BytesOnLastPageOfFile)
		fmt.Fprintf(w, "Pages In File:\t 0x%x\n", DOSHeader.PagesInFile)
		fmt.Fprintf(w, "Relocations:\t 0x%x\n", DOSHeader.Relocations)
		fmt.Fprintf(w, "Size Of Header:\t 0x%x\n", DOSHeader.SizeOfHeader)
		fmt.Fprintf(w, "Min Extra Paragraphs Needed:\t 0x%x\n", DOSHeader.MinExtraParagraphsNeeded)
		fmt.Fprintf(w, "Max Extra Paragraphs Needed:\t 0x%x\n", DOSHeader.MaxExtraParagraphsNeeded)
		fmt.Fprintf(w, "Initial SS:\t 0x%x\n", DOSHeader.InitialSS)
		fmt.Fprintf(w, "Initial SP:\t 0x%x\n", DOSHeader.InitialSP)
		fmt.Fprintf(w, "Checksum:\t 0x%x\n", DOSHeader.Checksum)
		fmt.Fprintf(w, "Initial IP:\t 0x%x\n", DOSHeader.InitialIP)
		fmt.Fprintf(w, "Initial CS:\t 0x%x\n", DOSHeader.InitialCS)
		fmt.Fprintf(w, "Address Of Relocation Table:\t 0x%x\n", DOSHeader.AddressOfRelocationTable)
		fmt.Fprintf(w, "Overlay Number:\t 0x%x\n", DOSHeader.OverlayNumber)
		fmt.Fprintf(w, "OEM Identifier:\t 0x%x\n", DOSHeader.OEMIdentifier)
		fmt.Fprintf(w, "OEM Information:\t 0x%x\n", DOSHeader.OEMInformation)
		fmt.Fprintf(w, "Address Of New EXE Header:\t 0x%x (%s)\n", DOSHeader.AddressOfNewEXEHeader, signature)
		w.Flush()
	}

	if cfg.wantRichHeader && pe.FileInfo.HasRichHdr {
		richHeader := pe.RichHeader
		fmt.Printf("RICH HEADER\n\n")
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 3, ' ', tabwriter.AlignRight)
		fmt.Fprintf(w, "\t0x%x\t XOR Key\n", richHeader.XORKey)
		fmt.Fprintf(w, "\t0x%x\t DanS offset\n", richHeader.DansOffset)
		fmt.Fprintf(w, "\t0x%x\t Checksum\n\n", pe.RichHeaderChecksum())
		fmt.Fprintln(w, "ProductID\tMinorCV\tCount\tUnmasked\tMeaning\tVSVersion\t")
		for _, compID := range pe.RichHeader.CompIDs {
			fmt.Fprintf(w, "0x%x\t0x%x\t0x%x\t0x%x\t%s\t%s\t\n",
				compID.ProdID, compID.MinorCV, compID.Count, compID.Unmasked,
				peparser.ProdIDtoStr(compID.ProdID), peparser.ProdIDtoVSversion(compID.ProdID))
		}
		w.Flush()
		fmt.Print("\n   ---Raw header dump---\n")
		hexDump(richHeader.Raw)
	}

	if cfg.wantNTHeader {
		ntHeader := pe.NtHeader.FileHeader
		unixTimeUTC := time.Unix(int64(ntHeader.TimeDateStamp), 0)
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 3, ' ', tabwriter.AlignRight)

		fmt.Print("\n\t------[ File Header ]------\n\n")
		fmt.Fprintf(w, "Machine:\t 0x%x (%s)\n", ntHeader.Machine, pe.PrettyMachineType())
		fmt.Fprintf(w, "Number Of Sections:\t 0x%x\n", ntHeader.NumberOfSections)
		fmt.Fprintf(w, "TimeDateStamp:\t 0x%x (%s)\n", ntHeader.TimeDateStamp, unixTimeUTC.String())
		fmt.Fprintf(w, "Pointer To Symbol Table:\t 0x%x\n", ntHeader.PointerToSymbolTable)
		fmt.Fprintf(w, "Number Of Symbols:\t 0x%x\n", ntHeader.NumberOfSymbols)
		fmt.Fprintf(w, "Number Of Symbols:\t 0x%x\n", ntHeader.NumberOfSymbols)
		fmt.Fprintf(w, "Size Of Optional Header:\t 0x%x\n", ntHeader.SizeOfOptionalHeader)
		fmt.Fprintf(w, "Characteristics:\t 0x%x\n", ntHeader.Characteristics)
		w.Flush()

		fmt.Print("\n\t------[ Optional Header ]------\n\n")
		if pe.Is64 {
			oh := pe.NtHeader.OptionalHeader.(peparser.ImageOptionalHeader64)
			dllCharacteristics := strings.Join(pe.PrettyDllCharacteristics(), " | ")
			fmt.Fprintf(w, "Magic:\t 0x%x (%s)\n", oh.Magic, pe.PrettyOptionalHeaderMagic())
			fmt.Fprintf(w, "Major Linker Version:\t 0x%x\n", oh.MajorLinkerVersion)
			fmt.Fprintf(w, "Minor Linker Version:\t 0x%x\n", oh.MinorLinkerVersion)
			fmt.Fprintf(w, "Size Of Code:\t 0x%x (%s)\n", oh.SizeOfCode, BytesSize(float64(oh.SizeOfCode)))
			fmt.Fprintf(w, "Size Of Initialized Data:\t 0x%x (%s)\n", oh.SizeOfInitializedData,
				BytesSize(float64(oh.SizeOfInitializedData)))
			fmt.Fprintf(w, "Size Of Uninitialized Data:\t 0x%x (%s)\n", oh.SizeOfUninitializedData,
				BytesSize(float64(oh.SizeOfUninitializedData)))
			fmt.Fprintf(w, "Address Of Entry Point:\t 0x%x\n", oh.AddressOfEntryPoint)
			fmt.Fprintf(w, "Base Of Code:\t 0x%x\n", oh.BaseOfCode)
			fmt.Fprintf(w, "Image Base:\t 0x%x\n", oh.ImageBase)
			fmt.Fprintf(w, "Section Alignment:\t 0x%x (%s)\n", oh.SectionAlignment,
				BytesSize(float64(oh.SectionAlignment)))
			fmt.Fprintf(w, "File Alignment:\t 0x%x (%s)\n", oh.FileAlignment,
				BytesSize(float64(oh.FileAlignment)))
			fmt.Fprintf(w, "Major OS Version:\t 0x%x\n", oh.MajorOperatingSystemVersion)
			fmt.Fprintf(w, "Minor OS Version:\t 0x%x\n", oh.MinorOperatingSystemVersion)
			fmt.Fprintf(w, "Major Image Version:\t 0x%x\n", oh.MajorImageVersion)
			fmt.Fprintf(w, "Minor Image Version:\t 0x%x\n", oh.MinorImageVersion)
			fmt.Fprintf(w, "Major Subsystem Version:\t 0x%x\n", oh.MajorSubsystemVersion)
			fmt.Fprintf(w, "Minor Subsystem Version:\t 0x%x\n", oh.MinorSubsystemVersion)
			fmt.Fprintf(w, "Win32 Version Value:\t 0x%x\n", oh.Win32VersionValue)
			fmt.Fprintf(w, "Size Of Image:\t 0x%x (%s)\n", oh.SizeOfImage, BytesSize(float64(oh.SizeOfImage)))
			fmt.Fprintf(w, "Size Of Headers:\t 0x%x (%s)\n", oh.SizeOfHeaders, BytesSize(float64(oh.SizeOfHeaders)))
			fmt.Fprintf(w, "Checksum:\t 0x%x\n", oh.CheckSum)
			fmt.Fprintf(w, "Subsystem:\t 0x%x (%s)\n", oh.Subsystem, pe.PrettySubsystem())
			fmt.Fprintf(w, "Dll Characteristics:\t 0x%x (%s)\n", oh.DllCharacteristics, dllCharacteristics)
			fmt.Fprintf(w, "Size Of Stack Reserve:\t 0x%x (%s)\n", oh.SizeOfStackReserve, BytesSize(float64(oh.SizeOfStackReserve)))
			fmt.Fprintf(w, "Size Of Stack Commit:\t 0x%x (%s)\n", oh.SizeOfStackCommit, BytesSize(float64(oh.SizeOfStackCommit)))
			fmt.Fprintf(w, "Size Of Heap Reserve:\t 0x%x (%s)\n", oh.SizeOfHeapReserve, BytesSize(float64(oh.SizeOfHeapReserve)))
			fmt.Fprintf(w, "Size Of Heap Commit:\t 0x%x (%s)\n", oh.SizeOfHeapCommit, BytesSize(float64(oh.SizeOfHeapCommit)))
			fmt.Fprintf(w, "Loader Flags:\t 0x%x\n", oh.LoaderFlags)
			fmt.Fprintf(w, "Number Of RVA And Sizes:\t 0x%x\n", oh.NumberOfRvaAndSizes)
			fmt.Fprintf(w, "\n")
			for entry := peparser.ImageDirectoryEntry(0); entry < peparser.ImageNumberOfDirectoryEntries; entry++ {
				rva := oh.DataDirectory[entry].VirtualAddress
				size := oh.DataDirectory[entry].Size
				fmt.Fprintf(w, "%s Table:\t RVA: 0x%0.8x\t Size:0x%0.8x\t\n", entry.String(), rva, size)
			}
		} else {
			oh := pe.NtHeader.OptionalHeader.(peparser.ImageOptionalHeader32)
			dllCharacteristics := strings.Join(pe.PrettyDllCharacteristics(), " | ")
			fmt.Fprintf(w, "Magic:\t 0x%x (%s)\n", oh.Magic, pe.PrettyOptionalHeaderMagic())
			fmt.Fprintf(w, "Major Linker Version:\t 0x%x\n", oh.MajorLinkerVersion)
			fmt.Fprintf(w, "Minor Linker Version:\t 0x%x\n", oh.MinorLinkerVersion)
			fmt.Fprintf(w, "Size Of Code:\t 0x%x (%s)\n", oh.SizeOfCode, BytesSize(float64(oh.SizeOfCode)))
			fmt.Fprintf(w, "Size Of Initialized Data:\t 0x%x (%s)\n", oh.SizeOfInitializedData,
				BytesSize(float64(oh.SizeOfInitializedData)))
			fmt.Fprintf(w, "Size Of Uninitialized Data:\t 0x%x (%s)\n", oh.SizeOfUninitializedData,
				BytesSize(float64(oh.SizeOfUninitializedData)))
			fmt.Fprintf(w, "Address Of Entry Point:\t 0x%x\n", oh.AddressOfEntryPoint)
			fmt.Fprintf(w, "Base Of Code:\t 0x%x\n", oh.BaseOfCode)
			fmt.Fprintf(w, "Image Base:\t 0x%x\n", oh.ImageBase)
			fmt.Fprintf(w, "Section Alignment:\t 0x%x (%s)\n", oh.SectionAlignment,
				BytesSize(float64(oh.SectionAlignment)))
			fmt.Fprintf(w, "File Alignment:\t 0x%x (%s)\n", oh.FileAlignment,
				BytesSize(float64(oh.FileAlignment)))
			fmt.Fprintf(w, "Major OS Version:\t 0x%x\n", oh.MajorOperatingSystemVersion)
			fmt.Fprintf(w, "Minor OS Version:\t 0x%x\n", oh.MinorOperatingSystemVersion)
			fmt.Fprintf(w, "Major Image Version:\t 0x%x\n", oh.MajorImageVersion)
			fmt.Fprintf(w, "Minor Image Version:\t 0x%x\n", oh.MinorImageVersion)
			fmt.Fprintf(w, "Major Subsystem Version:\t 0x%x\n", oh.MajorSubsystemVersion)
			fmt.Fprintf(w, "Minor Subsystem Version:\t 0x%x\n", oh.MinorSubsystemVersion)
			fmt.Fprintf(w, "Win32 Version Value:\t 0x%x\n", oh.Win32VersionValue)
			fmt.Fprintf(w, "Size Of Image:\t 0x%x (%s)\n", oh.SizeOfImage, BytesSize(float64(oh.SizeOfImage)))
			fmt.Fprintf(w, "Size Of Headers:\t 0x%x (%s)\n", oh.SizeOfHeaders, BytesSize(float64(oh.SizeOfHeaders)))
			fmt.Fprintf(w, "Checksum:\t 0x%x\n", oh.CheckSum)
			fmt.Fprintf(w, "Subsystem:\t 0x%x (%s)\n", oh.Subsystem, pe.PrettySubsystem())
			fmt.Fprintf(w, "Dll Characteristics:\t 0x%x (%s)\n", oh.DllCharacteristics, dllCharacteristics)
			fmt.Fprintf(w, "Size Of Stack Reserve:\t 0x%x (%s)\n", oh.SizeOfStackReserve, BytesSize(float64(oh.SizeOfStackReserve)))
			fmt.Fprintf(w, "Size Of Stack Commit:\t 0x%x (%s)\n", oh.SizeOfStackCommit, BytesSize(float64(oh.SizeOfStackCommit)))
			fmt.Fprintf(w, "Size Of Heap Reserve:\t 0x%x (%s)\n", oh.SizeOfHeapReserve, BytesSize(float64(oh.SizeOfHeapReserve)))
			fmt.Fprintf(w, "Size Of Heap Commit:\t 0x%x (%s)\n", oh.SizeOfHeapCommit, BytesSize(float64(oh.SizeOfHeapCommit)))
			fmt.Fprintf(w, "Loader Flags:\t 0x%x\n", oh.LoaderFlags)
			fmt.Fprintf(w, "Number Of RVA And Sizes:\t 0x%x\n", oh.NumberOfRvaAndSizes)
			fmt.Fprintf(w, "\n")
			for entry := peparser.ImageDirectoryEntry(0); entry < peparser.ImageNumberOfDirectoryEntries; entry++ {
				rva := oh.DataDirectory[entry].VirtualAddress
				size := oh.DataDirectory[entry].Size
				fmt.Fprintf(w, "%s Table:\t RVA: 0x%0.8x\t Size:0x%0.8x\t\n", entry.String(), rva, size)
			}
		}
		w.Flush()
	}

	if cfg.wantSections && pe.FileInfo.HasSections {
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 3, ' ', tabwriter.AlignRight)
		for i, sec := range pe.Sections {
			hdr := sec.Header
			fmt.Printf("\n\t------[ Section Header #%d ]------\n\n", i)
			fmt.Fprintf(w, "Name:\t %v (%s)\n", hdr.Name, sec.String())
			fmt.Fprintf(w, "Virtual Size:\t 0x%x (%s)\n", hdr.VirtualSize,
				BytesSize(float64(hdr.VirtualSize)))
			fmt.Fprintf(w, "Virtual Address:\t 0x%x\n", hdr.VirtualAddress)
			fmt.Fprintf(w, "Size Of Raw Data Size:\t 0x%x (%s)\n", hdr.SizeOfRawData,
				BytesSize(float64(hdr.SizeOfRawData)))
			fmt.Fprintf(w, "Pointer To Raw Data:\t 0x%x\n", hdr.PointerToRawData)
			fmt.Fprintf(w, "Pointer To Relocations:\t 0x%x\n", hdr.PointerToRelocations)
			fmt.Fprintf(w, "Pointer To Line Numbers:\t 0x%x\n", hdr.PointerToLineNumbers)
			fmt.Fprintf(w, "Number Of Relocations:\t 0x%x\n", hdr.NumberOfRelocations)
			fmt.Fprintf(w, "Number Of Line Numbers:\t 0x%x\n", hdr.NumberOfLineNumbers)
			fmt.Fprintf(w, "Characteristics:\t 0x%x (%s)\n", hdr.Characteristics,
				strings.Join(sec.PrettySectionFlags(), " | "))
			fmt.Fprintf(w, "Entropy:\t %f\n", sec.CalculateEntropy(pe))
			w.Flush()

			fmt.Fprintf(w, "\n")
			hexDumpSize(sec.Data(0, hdr.PointerToRawData, pe), 128)
		}
	}

	if cfg.wantImport && pe.FileInfo.HasImport {
		fmt.Printf("IMPORTS\n\n")
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 3, ' ', tabwriter.AlignRight)
		for _, imp := range pe.Imports {
			desc := imp.Descriptor
			fmt.Printf("\n\t------[ %s ]------\n\n", imp.Name)
			fmt.Fprintf(w, "Name:\t 0x%x\n", desc.Name)
			fmt.Fprintf(w, "Original First Thunk:\t 0x%x\n", desc.OriginalFirstThunk)
			fmt.Fprintf(w, "First Thunk:\t 0x%x\n", desc.FirstThunk)
			fmt.Fprintf(w, "TimeDateStamp:\t 0x%x\n", desc.TimeDateStamp)
			fmt.Fprintf(w, "Forwarder Chain:\t 0x%x\n", desc.ForwarderChain)
			fmt.Fprintf(w, "\n")
			fmt.Fprintln(w, "Name\tThunkRVA\tThunkValue\tOriginalThunkRVA\tOriginalThunkValue\tHint\t")
			for _, impFunc := range imp.Functions {
				fmt.Fprintf(w, "%s\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t\n",
					impFunc.Name, impFunc.ThunkRVA, impFunc.ThunkValue, impFunc.OriginalThunkRVA,
					impFunc.OriginalThunkValue, impFunc.Hint)
			}
			w.Flush()

		}
	}

	if cfg.wantResource && pe.FileInfo.HasResource {
		var printRsrcDir func(rsrcDir peparser.ResourceDirectory)
		padding := 0

		printRsrcDataEntry := func(entry peparser.ResourceDataEntry) {
			padding++
			w := tabwriter.NewWriter(os.Stdout, 1, 1, padding, ' ', 0)
			imgRsrcDataEntry := entry.Struct
			fmt.Fprintf(w, "\n\t\u27A1 Resource Data Entry\n\t")
			fmt.Fprintf(w, "|- Offset To Data: 0x%x\n\t", imgRsrcDataEntry.OffsetToData)
			fmt.Fprintf(w, "|- Size: 0x%x\n\t", imgRsrcDataEntry.Size)
			fmt.Fprintf(w, "|- Code Page: 0x%x\n\t", imgRsrcDataEntry.CodePage)
			fmt.Fprintf(w, "|- Reserved: 0x%x\n\t", imgRsrcDataEntry.Reserved)
			fmt.Fprintf(w, "|- Language: %d (%s)\n\t", entry.Lang, entry.Lang.String())
			fmt.Fprintf(w, "|- Sub-language: %s\n\t", peparser.PrettyResourceLang(entry.Lang, int(entry.SubLang)))
			w.Flush()
			padding--
		}

		printRsrcDir = func(rsrcDir peparser.ResourceDirectory) {
			padding++
			w := tabwriter.NewWriter(os.Stdout, 1, 1, padding, ' ', 0)
			imgRsrcDir := rsrcDir.Struct
			fmt.Fprintf(w, "\n\t\u27A1 Resource Directory\n\t")
			fmt.Fprintf(w, "|- Characteristics: 0x%x\n\t", imgRsrcDir.Characteristics)
			fmt.Fprintf(w, "|- TimeDateStamp: 0x%x\n\t", imgRsrcDir.TimeDateStamp)
			fmt.Fprintf(w, "|- Major Version: 0x%x\n\t", imgRsrcDir.MajorVersion)
			fmt.Fprintf(w, "|- Minor Version: 0x%x\n\t", imgRsrcDir.MinorVersion)
			fmt.Fprintf(w, "|- Number Of Named Entries: 0x%x\n\t", imgRsrcDir.NumberOfNamedEntries)
			fmt.Fprintf(w, "|- Number Of ID Entries: 0x%x\n\t", imgRsrcDir.NumberOfIDEntries)
			fmt.Fprintf(w, "|----------------------------------\n\t")
			padding++
			w.Flush()
			w = tabwriter.NewWriter(os.Stdout, 1, 1, padding, ' ', 0)
			for i, entry := range rsrcDir.Entries {
				fmt.Fprintf(w, "\t|- \u27A1 Resource Directory Entry %d, ID: %d", i+1, entry.ID)

				// Print the interpretation of a resource ID only in root node.
				if padding == 2 {
					if entry.ID <= peparser.RTManifest {
						fmt.Fprintf(w, " (%s)", peparser.ResourceType(entry.ID).String())
					}
				}
				fmt.Fprintf(w, "\n\t|- Name: 0x%x\n\t", entry.Struct.Name)
				if entry.Name != "" {
					fmt.Fprintf(w, " (%s)", entry.Name)
				}
				fmt.Fprintf(w, "|- Offset To Data: 0x%x\t", entry.Struct.OffsetToData)
				fmt.Fprintf(w, "\n\t|----------------------------------\t")
				w.Flush()
				if entry.IsResourceDir {
					printRsrcDir(entry.Directory)
				} else {
					printRsrcDataEntry(entry.Data)
				}

			}
			padding -= 2

		}

		fmt.Printf("\n\nRESOURCES\n**********\n")
		printRsrcDir(pe.Resources)
	}

	if cfg.wantCLR && pe.FileInfo.HasCLR {
		dotnetMetadata, _ := json.Marshal(pe.CLR)
		log.Info(prettyPrint(dotnetMetadata))
		if modTable, ok := pe.CLR.MetadataTables[peparser.Module]; ok {
			if modTable.Content != nil {
				modTableRow := modTable.Content.(peparser.ModuleTableRow)
				modName := pe.GetStringFromData(modTableRow.Name, pe.CLR.MetadataStreams["#Strings"])
				moduleName := string(modName)
				log.Info(moduleName)
			}
		}
	}

	if cfg.wantException && pe.FileInfo.HasException {
		fmt.Printf("\n\nEXCEPTIONS\n***********\n")
		for _, exception := range pe.Exceptions {
			entry := exception.RuntimeFunction
			fmt.Printf("\n\u27A1 BeginAddress: 0x%x EndAddress:0x%x UnwindInfoAddress:0x%x\t\n",
				entry.BeginAddress, entry.EndAddress, entry.UnwindInfoAddress)

			ui := exception.UnwinInfo
			handlerFlags := peparser.PrettyUnwindInfoHandlerFlags(ui.Flags)
			prettyFlags := strings.Join(handlerFlags, ",")
			fmt.Printf("|- Version: 0x%x\n", ui.Version)
			fmt.Printf("|- Flags: 0x%x", ui.Flags)
			if ui.Flags == 0 {
				fmt.Print(" (None)\n")
			} else {
				fmt.Printf(" (%s)\n", prettyFlags)
			}

			fmt.Printf("|- Size Of Prolog: 0x%x\n", ui.SizeOfProlog)
			fmt.Printf("|- Count Of Codes: 0x%x\n", ui.CountOfCodes)
			fmt.Printf("|- Exception Handler: 0x%x\n", ui.ExceptionHandler)
			fmt.Print("|- Unwind codes:\n")
			for _, uc := range ui.UnwindCodes {
				fmt.Printf("|-  * %.2x: %s, %s\n", uc.CodeOffset,
					peparser.PrettyUnwindOpcode(uc.UnwindOp), uc.Operand)
			}
		}
	}

	if cfg.wantCertificate && pe.FileInfo.HasCertificate {
		fmt.Printf("\nSECURITY\n*********\n")

		cert := pe.Certificates
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 3, ' ', tabwriter.AlignRight)
		fmt.Fprintln(w, "Length\tRevision\tCertificateType\t")
		fmt.Fprintf(w, "0x%x\t0x%x\t0x%x\t\n", cert.Header.Length, cert.Header.Revision,
			cert.Header.CertificateType)
		w.Flush()
		fmt.Print("\n   ---Raw Certificate dump---\n")
		hexDump(cert.Raw)
		fmt.Print("\n---Certificate ---\n\n")
		fmt.Fprintf(w, "Issuer Name:\t %s\n", cert.Info.Issuer)
		fmt.Fprintf(w, "Subject Name:\t %s\n", cert.Info.Subject)
		fmt.Fprintf(w, "Serial Number:\t %x\n", cert.Info.SerialNumber)
		fmt.Fprintf(w, "Validity From:\t %s to %s\n", cert.Info.NotBefore.String(), cert.Info.NotAfter.String())
		fmt.Fprintf(w, "Signature Algorithm:\t %s\n", cert.Info.SignatureAlgorithm.String())
		fmt.Fprintf(w, "PublicKey Algorithm:\t %s\n", cert.Info.PublicKeyAlgorithm.String())
		w.Flush()
	}

	fmt.Print("\n")
}
