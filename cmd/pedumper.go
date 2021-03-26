// Copyright 2021 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	peparser "github.com/saferwall/pe"
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
	clr         bool
)

func prettyPrint(buff []byte) string {
	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, buff, "", "\t")
	if error != nil {
		log.Println("JSON parse error: ", error)
		return string(buff)
	}

	return string(prettyJSON.Bytes())
}

func isDirectory(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fileInfo.IsDir()
}

func parsePE(filename string, cmd *cobra.Command) {
	log.Printf("Processing filename %s", filename)

	data, _ := ioutil.ReadFile(filename)
	pe, err := peparser.NewBytes(data, &peparser.Options{})

	// pe, err := peparser.New(filename, &peparser.Options{})
	if err != nil {
		log.Printf("Error while opening file: %s, reason: %s", filename, err)
		return
	}
	defer pe.Close()

	err = pe.Parse()
	if err != nil {
		log.Printf("Error while parsing file: %s, reason: %s", filename, err)
		return
	}

	wantDosHeader, _ := cmd.Flags().GetBool("dosheader")
	if wantDosHeader {
		dosHeader, _ := json.Marshal(pe.DosHeader)
		fmt.Println(prettyPrint(dosHeader))
	}

	wantNtHeader, _ := cmd.Flags().GetBool("ntheader")
	if wantNtHeader {
		ntHeader, _ := json.Marshal(pe.NtHeader)
		fmt.Println(prettyPrint(ntHeader))
	}

	wantSections, _ := cmd.Flags().GetBool("sections")
	if wantSections {
		sectionsHeaders, _ := json.Marshal(pe.Sections)
		fmt.Println(prettyPrint(sectionsHeaders))
	}

	wantCLR, _ := cmd.Flags().GetBool("clr")
	if wantCLR {
		dotnetMetadata, _ := json.Marshal(pe.CLR)
		fmt.Println(prettyPrint(dotnetMetadata))

		if modTable, ok := pe.CLR.MetadataTables[peparser.Module]; ok {
			if modTable.Content != nil {
				modTableRow := modTable.Content.(peparser.ModuleTableRow)
				modName := pe.GetStringFromData(modTableRow.Name, pe.CLR.MetadataStreams["#Strings"])
				moduleName := string(modName)
				log.Println(moduleName)
			}
		}

	}

	wantAll, _ := cmd.Flags().GetBool("all")
	if wantAll {
		dosHeader, _ := json.Marshal(pe.DosHeader)
		ntHeader, _ := json.Marshal(pe.NtHeader)
		sectionsHeaders, _ := json.Marshal(pe.Sections)
		fmt.Println(prettyPrint(dosHeader))
		fmt.Println(prettyPrint(ntHeader))
		fmt.Println(prettyPrint(sectionsHeaders))
	}
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
			fmt.Print("You are using version 0.0.1")
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
	dumpCmd.Flags().BoolVarP(&clr, "clr", "", false, "Dump .NET metadata")
	dumpCmd.Flags().BoolVarP(&all, "all", "", false, "Dump everything")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}
