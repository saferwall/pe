// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"text/tabwriter"

	peparser "github.com/saferwall/pe"
	"github.com/saferwall/pe/log"
	"github.com/spf13/cobra"
)

var (
	all         bool
	verbose     bool
	dosHeader   bool
	richHeader  bool
	ntHeader    bool
	directories bool
	sections    bool
	resources   bool
	clr         bool
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

func parsePE(filename string, cmd *cobra.Command) {

	logger := log.NewStdLogger(os.Stdout)
	logger = log.NewFilter(logger, log.FilterLevel(log.LevelError))
	log := log.NewHelper(logger)

	log.Infof("parsing filename %s", filename)

	data, _ := ioutil.ReadFile(filename)
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
	os.WriteFile("out.json", []byte(prettyPrint(b)), 0644)

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

	wantDosHeader, _ := cmd.Flags().GetBool("dosheader")
	if wantDosHeader {
		dosHeader, _ := json.Marshal(pe.DOSHeader)
		fmt.Print(prettyPrint(dosHeader))
	}

	wantRichHeader, _ := cmd.Flags().GetBool("rich")
	if wantRichHeader {
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

	wantNtHeader, _ := cmd.Flags().GetBool("ntheader")
	if wantNtHeader {
		ntHeader, _ := json.Marshal(pe.NtHeader)
		log.Info(prettyPrint(ntHeader))
	}

	wantSections, _ := cmd.Flags().GetBool("sections")
	if wantSections {
		for _, sec := range pe.Sections {
			log.Infof("Section Name : %s\n", sec.NameString())
			log.Infof("Section VirtualSize : %x\n", sec.Header.VirtualSize)
			log.Infof("Section Flags : %x, Meaning: %v\n\n",
				sec.Header.Characteristics, sec.PrettySectionFlags())
		}
		sectionsHeaders, _ := json.Marshal(pe.Sections)
		log.Info(prettyPrint(sectionsHeaders))
	}

	wantResources, _ := cmd.Flags().GetBool("resources")
	if wantResources {
		rsrc, _ := json.Marshal(pe.Resources)
		log.Info(prettyPrint(rsrc))
	}

	wantCLR, _ := cmd.Flags().GetBool("clr")
	if wantCLR {
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

	wantAll, _ := cmd.Flags().GetBool("all")
	if wantAll {
		dosHeader, _ := json.Marshal(pe.DOSHeader)
		ntHeader, _ := json.Marshal(pe.NtHeader)
		sectionsHeaders, _ := json.Marshal(pe.Sections)
		log.Info(prettyPrint(dosHeader))
		log.Info(prettyPrint(ntHeader))
		log.Info(prettyPrint(sectionsHeaders))
		return
	}

	fmt.Println()
}

func parse(cmd *cobra.Command, args []string) {
	filePath := args[0]

	// filePath points to a file.
	if !isDirectory(filePath) {
		parsePE(filePath, cmd)

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
			parsePE(file, cmd)
		}
	}
}

func main() {

	var rootCmd = &cobra.Command{
		Use:   "pedumper",
		Short: "A Portable Executable file parser",
		Long:  "A PE-Parser built for speed and malware-analysis in mind by Saferwall",
		Run: func(cmd *cobra.Command, args []string) {
		},
	}

	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print version number",
		Long:  "Print version number",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print("You are using version 1.1.7")
		},
	}

	var dumpCmd = &cobra.Command{
		Use:   "dump",
		Short: "Dumps the file",
		Long:  "Dumps interesting structure of the Portable Executable file",
		Args:  cobra.MinimumNArgs(1),
		Run:   parse,
	}

	// Init root command.
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(dumpCmd)

	// Init flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
	dumpCmd.Flags().BoolVarP(&dosHeader, "dosheader", "", false, "Dump DOS header")
	dumpCmd.Flags().BoolVarP(&richHeader, "rich", "", false, "Dump Rich header")
	dumpCmd.Flags().BoolVarP(&ntHeader, "ntheader", "", false, "Dump NT header")
	dumpCmd.Flags().BoolVarP(&directories, "directories", "", false, "Dump data directories")
	dumpCmd.Flags().BoolVarP(&sections, "sections", "", false, "Dump section headers")
	dumpCmd.Flags().BoolVarP(&resources, "resources", "", false, "Dump resources")
	dumpCmd.Flags().BoolVarP(&clr, "clr", "", false, "Dump .NET metadata")
	dumpCmd.Flags().BoolVarP(&all, "all", "", false, "Dump everything")

	if err := rootCmd.Execute(); err != nil {
		fmt.Print(err)
		os.Exit(1)
	}
}
