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
	"text/tabwriter"

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
		dosHeader, _ := json.Marshal(pe.DOSHeader)
		fmt.Print(prettyPrint(dosHeader))
	}

	if cfg.wantRichHeader {
		richheader := pe.RichHeader
		fmt.Printf("RICH HEADER\n\n")
		w := tabwriter.NewWriter(os.Stdout, 1, 1, 3, ' ', tabwriter.AlignRight)
		fmt.Fprintf(w, "\t0x%x\t xor Key\n", richheader.XorKey)
		fmt.Fprintf(w, "\t0x%x\t DanS offset\n", richheader.DansOffset)
		fmt.Fprintf(w, "\t0x%x\t checksum\n\n", pe.RichHeaderChecksum())
		fmt.Fprintln(w, "ProductID\tMinorCV\tCount\tUnmasked\tMeaning\tVSVersion\t")
		for _, compID := range pe.RichHeader.CompIDs {
			fmt.Fprintf(w, "0x%x\t0x%x\t0x%x\t0x%x\t%s\t%s\t\n",
				compID.ProdID, compID.MinorCV, compID.Count, compID.Unmasked,
				peparser.ProdIDtoStr(compID.ProdID), peparser.ProdIDtoVSversion(compID.ProdID))
		}
		w.Flush()
		fmt.Print("\n   ---Raw header dump---\n")
		hexDump(richheader.Raw)
	}

	if cfg.wantNTHeader {
		ntHeader, _ := json.Marshal(pe.NtHeader)
		log.Info(prettyPrint(ntHeader))
	}

	if cfg.wantSections {
		for _, sec := range pe.Sections {
			log.Infof("Section Name : %s\n", sec.NameString())
			log.Infof("Section VirtualSize : %x\n", sec.Header.VirtualSize)
			log.Infof("Section Flags : %x, Meaning: %v\n\n",
				sec.Header.Characteristics, sec.PrettySectionFlags())
		}
		sectionsHeaders, _ := json.Marshal(pe.Sections)
		log.Info(prettyPrint(sectionsHeaders))
	}

	if cfg.wantCLR {
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

	fmt.Println()
}
