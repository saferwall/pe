// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"text/tabwriter"
	"time"
	"unicode"
	"unsafe"

	peparser "github.com/saferwall/pe"
	"github.com/saferwall/pe/log"
)

var (
	wg   sync.WaitGroup
	jobs chan string = make(chan string)
)

func loopFilesWorker(cfg config) error {
	for path := range jobs {
		files, err := os.ReadDir(path)
		if err != nil {
			wg.Done()
			return err
		}

		for _, file := range files {
			if !file.IsDir() {
				fullpath := filepath.Join(path, file.Name())
				parsePE(fullpath, cfg)
			}
		}
		wg.Done()
	}
	return nil
}

func LoopDirsFiles(path string) error {
	files, err := os.ReadDir(path)
	if err != nil {
		return err
	}

	go func() {
		wg.Add(1)
		jobs <- path
	}()
	for _, file := range files {
		if file.IsDir() {
			LoopDirsFiles(filepath.Join(path, file.Name()))
		}
	}
	return nil
}

func prettyPrint(iface interface{}) string {
	var prettyJSON bytes.Buffer
	buff, _ := json.Marshal(iface)
	err := json.Indent(&prettyJSON, buff, "", "\t")
	if err != nil {
		log.Errorf("JSON parse error: %v", err)
		return string(buff)
	}

	return prettyJSON.String()
}

func humanizeTimestamp(ts uint32) string {
	unixTimeUTC := time.Unix(int64(ts), 0)
	return unixTimeUTC.String()
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

	// Append null bytes when length of the buffer
	// is smaller than the requested size.
	if len(b) < size {
		temp := make([]byte, size)
		copy(temp, b)
		b = temp
	}

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

func sentenceCase(s string) string {
	newString := string(s[0])
	for i, r := range s[1:] {
		if unicode.IsLower(r) && unicode.IsLetter(r) {
			newString += string(r)
		} else {
			if i < len(s)-2 {
				nextChar := rune(s[i+2])
				previousChar := rune(s[i])
				if unicode.IsLower(previousChar) && unicode.IsLetter(previousChar) {
					newString += " " + string(r)
				} else {
					if unicode.IsLower(nextChar) && unicode.IsLetter(nextChar) {
						newString += " " + string(r)
					} else {
						newString += string(r)
					}
				}
			}
		}
	}

	return newString
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
		Logger:                logger,
		DisableCertValidation: false,
		Fast:                  false,
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
	// f, err := os.Create("out.json")
	// if err != nil {
	// 	return
	// }
	// defer f.Close()
	// f.WriteString(prettyPrint(pe))

	if cfg.wantDOSHeader {
		DOSHeader := pe.DOSHeader
		magic := string(IntToByteArray(uint64(DOSHeader.Magic)))
		signature := string(IntToByteArray(uint64(pe.NtHeader.Signature)))
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 3, ' ', tabwriter.AlignRight)
		fmt.Print("\n\t------[ DOS Header ]------\n\n")
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
		fmt.Printf("\nRICH HEADER\n***********\n")
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
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 3, ' ', tabwriter.AlignRight)
		characteristics := strings.Join(ntHeader.Characteristics.String(), " | ")

		fmt.Print("\n\t------[ File Header ]------\n\n")
		fmt.Fprintf(w, "Machine:\t 0x%x (%s)\n", int(ntHeader.Machine), ntHeader.Machine.String())
		fmt.Fprintf(w, "Number Of Sections:\t 0x%x\n", ntHeader.NumberOfSections)
		fmt.Fprintf(w, "TimeDateStamp:\t 0x%x (%s)\n", ntHeader.TimeDateStamp, humanizeTimestamp(ntHeader.TimeDateStamp))
		fmt.Fprintf(w, "Pointer To Symbol Table:\t 0x%x\n", ntHeader.PointerToSymbolTable)
		fmt.Fprintf(w, "Number Of Symbols:\t 0x%x\n", ntHeader.NumberOfSymbols)
		fmt.Fprintf(w, "Number Of Symbols:\t 0x%x\n", ntHeader.NumberOfSymbols)
		fmt.Fprintf(w, "Size Of Optional Header:\t 0x%x\n", ntHeader.SizeOfOptionalHeader)
		fmt.Fprintf(w, "Characteristics:\t 0x%x (%s)\n", ntHeader.Characteristics, characteristics)
		w.Flush()

		fmt.Print("\n\t------[ Optional Header ]------\n\n")
		if pe.Is64 {
			oh := pe.NtHeader.OptionalHeader.(peparser.ImageOptionalHeader64)
			dllCharacteristics := strings.Join(oh.DllCharacteristics.String(), " | ")
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
			fmt.Fprintf(w, "Subsystem:\t 0x%x (%s)\n", uint16(oh.Subsystem), oh.Subsystem.String())
			fmt.Fprintf(w, "Dll Characteristics:\t 0x%x (%s)\n", uint16(oh.DllCharacteristics), dllCharacteristics)
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
			dllCharacteristics := strings.Join(oh.DllCharacteristics.String(), " | ")
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
			fmt.Fprintf(w, "Subsystem:\t 0x%x (%s)\n", uint16(oh.Subsystem), oh.Subsystem.String())
			fmt.Fprintf(w, "Dll Characteristics:\t 0x%x (%s)\n", uint16(oh.DllCharacteristics), dllCharacteristics)
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

	if cfg.wantCOFF && pe.FileInfo.HasCOFF {
		fmt.Printf("\nCOFF\n****\n")
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 3, ' ', tabwriter.AlignRight)
		fmt.Fprintln(w, "Name\tValue\tSectionNumber\tType\tStorageClass\tNumberOfAuxSymbols\t")
		for _, sym := range pe.COFF.SymbolTable {
			symName, _ := sym.String(pe)
			fmt.Fprintf(w, "%s\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t\n",
				symName, sym.Value, sym.SectionNumber,
				sym.Type, sym.StorageClass, sym.NumberOfAuxSymbols)
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
		fmt.Printf("\nIMPORTS\n********\n")
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 3, ' ', tabwriter.AlignRight)
		for _, imp := range pe.Imports {
			desc := imp.Descriptor
			fmt.Printf("\n\t------[ %s ]------\n\n", imp.Name)
			fmt.Fprintf(w, "Name:\t 0x%x\n", desc.Name)
			fmt.Fprintf(w, "Original First Thunk:\t 0x%x\n", desc.OriginalFirstThunk)
			fmt.Fprintf(w, "First Thunk:\t 0x%x\n", desc.FirstThunk)
			fmt.Fprintf(w, "TimeDateStamp:\t 0x%x (%s\n", desc.TimeDateStamp,
				humanizeTimestamp(desc.TimeDateStamp))
			fmt.Fprintf(w, "Forwarder Chain:\t 0x%x\n", desc.ForwarderChain)
			fmt.Fprintf(w, "\n")
			fmt.Fprintln(w, "Name\tThunkRVA\tThunkValue\tOriginalThunkRVA\tOriginalThunkValue\tHint\t")
			for _, impFunc := range imp.Functions {
				fmt.Fprintf(w, "%s\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t\n",
					impFunc.Name, impFunc.ThunkRVA, impFunc.ThunkValue,
					impFunc.OriginalThunkRVA, impFunc.OriginalThunkValue, impFunc.Hint)
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

		fmt.Printf("\nRESOURCES\n**********\n")
		printRsrcDir(pe.Resources)

		versionInfo, err := pe.ParseVersionResources()
		if err != nil {
			log.Errorf("failed to parse version resources: %v", err)
		} else {
			fmt.Printf("\nVersion Info: %v", prettyPrint(versionInfo))
		}
	}

	if cfg.wantException && pe.FileInfo.HasException {
		fmt.Printf("\nEXCEPTIONS\n***********\n")
		for _, exception := range pe.Exceptions {
			entry := exception.RuntimeFunction
			fmt.Printf("\n\u27A1 BeginAddress: 0x%x EndAddress:0x%x UnwindInfoAddress:0x%x\t\n",
				entry.BeginAddress, entry.EndAddress, entry.UnwindInfoAddress)

			ui := exception.UnwindInfo
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
					uc.UnwindOp.String(), uc.Operand)
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
		for _, cert := range cert.Certificates {
			fmt.Print("\n---Certificate ---\n\n")
			fmt.Fprintf(w, "Issuer Name:\t %s\n", cert.Info.Issuer)
			fmt.Fprintf(w, "Subject Name:\t %s\n", cert.Info.Subject)
			fmt.Fprintf(w, "Serial Number:\t %x\n", cert.Info.SerialNumber)
			fmt.Fprintf(w, "Validity From:\t %s to %s\n", cert.Info.NotBefore.String(), cert.Info.NotAfter.String())
			fmt.Fprintf(w, "Signature Algorithm:\t %s\n", cert.Info.SignatureAlgorithm.String())
			fmt.Fprintf(w, "PublicKey Algorithm:\t %s\n", cert.Info.PublicKeyAlgorithm.String())
			fmt.Fprintf(w, "Certificate valid:\t %v\n", cert.Verified)
			fmt.Fprintf(w, "Signature valid:\t %v\n", cert.SignatureValid)
			w.Flush()
		}

		// Calculate the PE authentihash.
		pe.Authentihash()
	}

	if cfg.wantReloc && pe.FileInfo.HasReloc {
		fmt.Printf("\nRELOCATIONS\n***********\n")
		for _, reloc := range pe.Relocations {
			fmt.Printf("\n\u27A1 Virtual Address: 0x%x | Size Of Block:0x%x | Entries Count:0x%x\t\n",
				reloc.Data.VirtualAddress, reloc.Data.SizeOfBlock, len(reloc.Entries))
			fmt.Print("|- Entries:\n")
			for _, relocEntry := range reloc.Entries {
				fmt.Printf("|-  Data: 0x%x |  Offset: 0x%x | Type:0x%x (%s)\n", relocEntry.Data,
					relocEntry.Offset, relocEntry.Type, relocEntry.Type.String(pe))
			}
		}
	}

	if cfg.wantDebug && pe.FileInfo.HasDebug {
		fmt.Printf("\nDEBUGS\n*******\n")
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 3, ' ', tabwriter.AlignRight)
		for _, debug := range pe.Debugs {
			imgDbgDir := debug.Struct
			fmt.Fprintf(w, "\n\t------[ %s ]------\n", debug.Type)
			fmt.Fprintf(w, "Characteristics:\t 0x%x\n", imgDbgDir.Characteristics)
			fmt.Fprintf(w, "TimeDateStamp:\t 0x%x (%s)\n", imgDbgDir.TimeDateStamp,
				humanizeTimestamp(imgDbgDir.TimeDateStamp))
			fmt.Fprintf(w, "Major Version:\t 0x%x\n", imgDbgDir.MajorVersion)
			fmt.Fprintf(w, "Minor Version:\t 0x%x\n", imgDbgDir.MinorVersion)
			fmt.Fprintf(w, "Type:\t 0x%x\n", imgDbgDir.Type)
			fmt.Fprintf(w, "Size Of Data:\t 0x%x (%s)\n", imgDbgDir.SizeOfData,
				BytesSize(float64(imgDbgDir.SizeOfData)))
			fmt.Fprintf(w, "Address Of Raw Data:\t 0x%x\n", imgDbgDir.AddressOfRawData)
			fmt.Fprintf(w, "Pointer To Raw Data:\t 0x%x\n", imgDbgDir.PointerToRawData)
			fmt.Fprintf(w, "\n")
			switch imgDbgDir.Type {
			case peparser.ImageDebugTypeCodeView:
				debugSignature, err := pe.ReadUint32(imgDbgDir.PointerToRawData)
				if err != nil {
					continue
				}
				if debugSignature == peparser.CVSignatureRSDS {
					pdb := debug.Info.(peparser.CVInfoPDB70)
					fmt.Fprintf(w, "CV Signature:\t 0x%x (%s)\n", pdb.CVSignature,
						pdb.CVSignature.String())
					fmt.Fprintf(w, "Signature:\t %s\n", pdb.Signature.String())
					fmt.Fprintf(w, "Age:\t 0x%x\n", pdb.Age)
					fmt.Fprintf(w, "PDB FileName:\t %s\n", pdb.PDBFileName)
				} else if debugSignature == peparser.CVSignatureNB10 {
					pdb := debug.Info.(peparser.CVInfoPDB20)
					fmt.Fprintf(w, "CV Header Signature:\t 0x%x (%s)\n",
						pdb.CVHeader.Signature, pdb.CVHeader.Signature.String())
					fmt.Fprintf(w, "CV Header Offset:\t 0x%x\n", pdb.CVHeader.Offset)
					fmt.Fprintf(w, "Signature:\t 0x%x (%s)\n", pdb.Signature,
						humanizeTimestamp(pdb.Signature))
					fmt.Fprintf(w, "Age:\t 0x%x\n", pdb.Age)
					fmt.Fprintf(w, "PDBFileName:\t %s\n", pdb.PDBFileName)

				}
			case peparser.ImageDebugTypePOGO:
				pogo := debug.Info.(peparser.POGO)
				if len(pogo.Entries) > 0 {
					fmt.Fprintf(w, "Signature:\t 0x%x (%s)\n\n", pogo.Signature,
						pogo.Signature.String())
					fmt.Fprintln(w, "RVA\tSize\tName\tDescription\t")
					fmt.Fprintln(w, "---\t----\t----\t-----------\t")
					for _, pogoEntry := range pogo.Entries {
						fmt.Fprintf(w, "0x%x\t0x%x\t%s\t%s\t\n", pogoEntry.RVA,
							pogoEntry.Size, pogoEntry.Name,
							peparser.SectionAttributeDescription(pogoEntry.Name))
					}
				}
			case peparser.ImageDebugTypeRepro:
				repro := debug.Info.(peparser.REPRO)
				fmt.Fprintf(w, "Hash:\t %x\n", repro.Hash)
				fmt.Fprintf(w, "Size:\t 0x%x (%s)\n", repro.Size, BytesSize(float64(repro.Size)))
			case peparser.ImageDebugTypeExDllCharacteristics:
				exDllCharacteristics := debug.Info.(peparser.DllCharacteristicsExType)
				fmt.Fprintf(w, "Value:\t %d (%s)\n", exDllCharacteristics,
					exDllCharacteristics.String())
			case peparser.ImageDebugTypeVCFeature:
				VCFeature := debug.Info.(peparser.VCFeature)
				fmt.Fprintf(w, "Pre VC11:\t 0x%x\n", VCFeature.PreVC11)
				fmt.Fprintf(w, "C/C++:\t 0x%x\n", VCFeature.CCpp)
				fmt.Fprintf(w, "/GS:\t 0x%x\n", VCFeature.Gs)
				fmt.Fprintf(w, "/sdl:\t 0x%x\n", VCFeature.Sdl)
				fmt.Fprintf(w, "GuardN:\t 0x%x\n", VCFeature.GuardN)
			case peparser.ImageDebugTypeFPO:
				fpo := debug.Info.([]peparser.FPOData)
				if len(fpo) > 0 {
					fmt.Fprintln(w, "OffsetStart\tProcSize\tNumLocals\tParamsSize\tPrologLength\tSavedRegsCount\tHasSEH\tUseBP\tReserved\tFrameType\t")
					fmt.Fprintln(w, "------\t------\t------\t------\t------\t------\t------\t------\t------\t------\t")
					for _, fpoData := range fpo {
						fmt.Fprintf(w, "0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t%d (%s)\t\n",
							fpoData.OffsetStart, fpoData.ProcSize, fpoData.NumLocals,
							fpoData.ParamsSize, fpoData.PrologLength,
							fpoData.SavedRegsCount, fpoData.HasSEH, fpoData.UseBP,
							fpoData.Reserved, fpoData.FrameType, fpoData.FrameType.String())
					}
				}
			}
		}

		w.Flush()
	}

	if cfg.wantBoundImp && pe.FileInfo.HasBoundImp {
		fmt.Printf("\nBOUND IMPORTS\n************\n")

		w := tabwriter.NewWriter(os.Stdout, 1, 1, 3, ' ', tabwriter.AlignRight)
		for _, bndImp := range pe.BoundImports {
			fmt.Printf("\n\t------[ %s ]------\n\n", bndImp.Name)
			fmt.Fprintf(w, "TimeDateStamp:\t 0x%x (%s)\n", bndImp.Struct.TimeDateStamp,
				humanizeTimestamp(bndImp.Struct.TimeDateStamp))
			fmt.Fprintf(w, "Offset Module  Name:\t 0x%x\n", bndImp.Struct.OffsetModuleName)
			fmt.Fprintf(w, "# Module Forwarder Refs:\t 0x%x\n", bndImp.Struct.NumberOfModuleForwarderRefs)
			fmt.Fprintf(w, "\n")
			if len(bndImp.ForwardedRefs) > 0 {
				fmt.Fprintln(w, "Name\tTimeDateStamp\tOffsetModuleName\tReserved\t")
				for _, fr := range bndImp.ForwardedRefs {
					fmt.Fprintf(w, "%s\t0x%x\t0x%x\t0x%x\t\n", fr.Name,
						fr.Struct.TimeDateStamp, fr.Struct.OffsetModuleName,
						fr.Struct.Reserved)
				}
			}
			w.Flush()
		}
	}

	if cfg.wantTLS && pe.FileInfo.HasTLS {
		fmt.Printf("\nTLS\n*****\n\n")

		tls := pe.TLS
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 3, ' ', tabwriter.AlignRight)
		if pe.Is64 {
			imgTLSDirectory64 := tls.Struct.(peparser.ImageTLSDirectory64)
			fmt.Fprintf(w, "Start Address Of Raw Data:\t 0x%x\n", imgTLSDirectory64.StartAddressOfRawData)
			fmt.Fprintf(w, "End Address Of Raw Data:\t 0x%x\n", imgTLSDirectory64.EndAddressOfRawData)
			fmt.Fprintf(w, "Address Of Index:\t %x\n", imgTLSDirectory64.AddressOfIndex)
			fmt.Fprintf(w, "Address Of CallBacks:\t 0x%x\n", imgTLSDirectory64.AddressOfCallBacks)
			fmt.Fprintf(w, "Size Of Zero Fill:\t 0x%x\n", imgTLSDirectory64.SizeOfZeroFill)
			fmt.Fprintf(w, "Characteristics:\t 0x%x (%s)\n", imgTLSDirectory64.Characteristics,
				imgTLSDirectory64.Characteristics.String())
			fmt.Fprintf(w, "Callbacks:\n")
			if len(tls.Callbacks.([]uint64)) > 0 {
				for _, callback := range tls.Callbacks.([]uint64) {
					fmt.Fprintf(w, "0x%x\t\n", callback)
				}
			}
		} else {
			imgTLSDirectory32 := tls.Struct.(peparser.ImageTLSDirectory32)
			fmt.Fprintf(w, "Start Address Of Raw Data:\t 0x%x\n", imgTLSDirectory32.StartAddressOfRawData)
			fmt.Fprintf(w, "End Address Of Raw Data:\t 0x%x\n", imgTLSDirectory32.EndAddressOfRawData)
			fmt.Fprintf(w, "Address Of Index:\t %x\n", imgTLSDirectory32.AddressOfIndex)
			fmt.Fprintf(w, "Address Of CallBacks:\t 0x%x\n", imgTLSDirectory32.AddressOfCallBacks)
			fmt.Fprintf(w, "Size Of Zero Fill:\t 0x%x\n", imgTLSDirectory32.SizeOfZeroFill)
			fmt.Fprintf(w, "Characteristics:\t 0x%x (%s)\n", imgTLSDirectory32.Characteristics,
				imgTLSDirectory32.Characteristics.String())
			fmt.Fprintf(w, "Callbacks:\n")
			if len(tls.Callbacks.([]uint32)) > 0 {
				for _, callback := range tls.Callbacks.([]uint32) {
					fmt.Fprintf(w, "0x%x\t\n", callback)
				}
			}
		}

		w.Flush()
	}

	if cfg.wantLoadCfg && pe.FileInfo.HasLoadCFG {
		fmt.Printf("\nLOAD CONFIG\n************\n\n")

		loadConfig := pe.LoadConfig
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 3, ' ', tabwriter.TabIndent)
		v := reflect.ValueOf(loadConfig.Struct)
		typeOfS := v.Type()
		imgLoadConfigDirectorySize := v.Field(0).Interface().(uint32)
		tmp := uint32(0)
		for i := 0; i < v.NumField(); i++ {
			// Do not print the fields of the image load config directory structure
			// that does not belong to it.
			tmp += uint32(binary.Size((v.Field(i).Interface())))
			if tmp > imgLoadConfigDirectorySize {
				break
			}
			fmt.Fprintf(w, "  %s\t : 0x%v\n", sentenceCase(typeOfS.Field(i).Name),
				v.Field(i).Interface())
		}
		w.Flush()
	}

	if cfg.wantCLR && pe.FileInfo.HasCLR {
		fmt.Printf("\nCLR\n****\n")

		fmt.Print("\n\t------[ CLR Header ]------\n\n")
		clr := pe.CLR
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 3, ' ', tabwriter.AlignRight)

		clrHdr := clr.CLRHeader
		flags := strings.Join(clrHdr.Flags.String(), " | ")
		fmt.Fprintf(w, "Size Of Header:\t 0x%x\n", clrHdr.Cb)
		fmt.Fprintf(w, "Major Runtime Version:\t 0x%x\n", clrHdr.MajorRuntimeVersion)
		fmt.Fprintf(w, "Minor Runtime Version:\t 0x%x\n", clrHdr.MinorRuntimeVersion)
		fmt.Fprintf(w, "MetaData RVA:\t 0x%x\n", clrHdr.MetaData.VirtualAddress)
		fmt.Fprintf(w, "MetaData Size:\t 0x%x\n", clrHdr.MetaData.Size)
		fmt.Fprintf(w, "Flags:\t 0x%x (%v)\n", clrHdr.Flags, flags)
		fmt.Fprintf(w, "EntryPoint RVA or Token:\t 0x%x\n", clrHdr.EntryPointRVAorToken)
		fmt.Fprintf(w, "Resources RVA:\t 0x%x\n", clrHdr.Resources.VirtualAddress)
		fmt.Fprintf(w, "Resources Size:\t 0x%x (%s)\n", clrHdr.Resources.Size, BytesSize(float64(clrHdr.Resources.Size)))
		fmt.Fprintf(w, "Strong Name Signature RVA:\t 0x%x\n", clrHdr.StrongNameSignature.VirtualAddress)
		fmt.Fprintf(w, "Strong Name Signature Size:\t 0x%x (%s)\n", clrHdr.StrongNameSignature.Size, BytesSize(float64(clrHdr.StrongNameSignature.Size)))
		fmt.Fprintf(w, "Code Manager Table RVA:\t 0x%x\n", clrHdr.CodeManagerTable.VirtualAddress)
		fmt.Fprintf(w, "Code Manager Table Size:\t 0x%x (%s)\n", clrHdr.CodeManagerTable.Size, BytesSize(float64(clrHdr.CodeManagerTable.Size)))
		fmt.Fprintf(w, "VTable Fixups RVA:\t 0x%x\n", clrHdr.VTableFixups.VirtualAddress)
		fmt.Fprintf(w, "VTable Fixups Size:\t 0x%x (%s)\n", clrHdr.VTableFixups.Size, BytesSize(float64(clrHdr.VTableFixups.Size)))
		fmt.Fprintf(w, "Export Address Table Jumps RVA:\t 0x%x\n", clrHdr.ExportAddressTableJumps.VirtualAddress)
		fmt.Fprintf(w, "Export Address Table Jumps Size:\t 0x%x (%s)\n", clrHdr.ExportAddressTableJumps.Size, BytesSize(float64(clrHdr.ExportAddressTableJumps.Size)))
		fmt.Fprintf(w, "Managed Native Header RVA:\t 0x%x\n", clrHdr.ManagedNativeHeader.VirtualAddress)
		fmt.Fprintf(w, "Managed Native Header Size:\t 0x%x (%s)\n", clrHdr.ManagedNativeHeader.Size, BytesSize(float64(clrHdr.ManagedNativeHeader.Size)))
		w.Flush()

		fmt.Print("\n\t------[ MetaData Header ]------\n\n")
		mdHdr := clr.MetadataHeader
		fmt.Fprintf(w, "Signature:\t 0x%x (%s)\n", mdHdr.Signature,
			string(IntToByteArray(uint64(mdHdr.Signature))))
		fmt.Fprintf(w, "Major Version:\t 0x%x\n", mdHdr.MajorVersion)
		fmt.Fprintf(w, "Minor Version:\t 0x%x\n", mdHdr.MinorVersion)
		fmt.Fprintf(w, "Extra Data:\t 0x%x\n", mdHdr.ExtraData)
		fmt.Fprintf(w, "Version String Length:\t 0x%x\n", mdHdr.VersionString)
		fmt.Fprintf(w, "Version String:\t %s\n", mdHdr.Version)
		fmt.Fprintf(w, "Flags:\t 0x%x\n", mdHdr.Flags)
		fmt.Fprintf(w, "Streams Count:\t 0x%x\n", mdHdr.Streams)
		w.Flush()

		fmt.Print("\n\t------[ MetaData Streams ]------\n\n")
		for _, sh := range clr.MetadataStreamHeaders {
			fmt.Fprintf(w, "Stream Name:\t %s\n", sh.Name)
			fmt.Fprintf(w, "Offset:\t 0x%x\n", sh.Offset)
			fmt.Fprintf(w, "Size:\t 0x%x (%s)\n", sh.Size, BytesSize(float64(sh.Size)))
			w.Flush()
			fmt.Print("\n   ---Stream Content---\n")
			hexDumpSize(clr.MetadataStreams[sh.Name], 128)
			fmt.Print("\n")
		}

		fmt.Print("\n\t------[ MetaData Tables Stream Header ]------\n\n")
		mdTablesStreamHdr := clr.MetadataTablesStreamHeader
		fmt.Fprintf(w, "Reserved:\t 0x%x\n", mdTablesStreamHdr.Reserved)
		fmt.Fprintf(w, "Major Version:\t 0x%x\n", mdTablesStreamHdr.MajorVersion)
		fmt.Fprintf(w, "Minor Version:\t 0x%x\n", mdTablesStreamHdr.MinorVersion)
		fmt.Fprintf(w, "Heaps:\t 0x%x\n", mdTablesStreamHdr.Heaps)
		fmt.Fprintf(w, "RID:\t 0x%x\n", mdTablesStreamHdr.RID)
		fmt.Fprintf(w, "MaskValid:\t 0x%x\n", mdTablesStreamHdr.MaskValid)
		fmt.Fprintf(w, "Sorted:\t 0x%x\n", mdTablesStreamHdr.Sorted)
		w.Flush()

		fmt.Print("\n\t------[ MetaData Tables ]------\n\n")
		mdTables := clr.MetadataTables
		for _, mdTable := range mdTables {
			fmt.Fprintf(w, "Name:\t %s | Items Count:\t 0x%x\n", mdTable.Name, mdTable.CountCols)
		}
		w.Flush()

		for table, modTable := range pe.CLR.MetadataTables {
			switch table {
			case peparser.Module:
				fmt.Print("\n\t[Modules]\n\t---------\n")
				modTableRow := modTable.Content.(peparser.ModuleTableRow)
				modName := pe.GetStringFromData(modTableRow.Name, pe.CLR.MetadataStreams["#Strings"])
				Mvid := pe.GetStringFromData(modTableRow.Mvid, pe.CLR.MetadataStreams["#GUID"])
				MvidStr := hex.EncodeToString(Mvid)
				fmt.Fprintf(w, "Generation:\t 0x%x\n", modTableRow.Generation)
				fmt.Fprintf(w, "Name:\t 0x%x (%s)\n", modTableRow.Name, string(modName))
				fmt.Fprintf(w, "Mvid:\t 0x%x (%s)\n", modTableRow.Mvid, MvidStr)
				fmt.Fprintf(w, "EncID:\t 0x%x\n", modTableRow.EncID)
				fmt.Fprintf(w, "EncBaseID:\t 0x%x\n", modTableRow.EncBaseID)
				w.Flush()

			}
		}
	}

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

	// Calculate the PE checksum.
	pe.Checksum()

	fmt.Print("\n")
}
