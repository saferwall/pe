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

func isDirectory(path string) bool {
	fileInfo, err := os.Stat(path)
	if err != nil {
		return false
	}
	return fileInfo.IsDir()
}

func parsePE(filename string, cmd *cobra.Command) {

	logger := log.NewStdLogger(os.Stdout)
	logger = log.NewFilter(logger, log.FilterLevel(log.LevelInfo))
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

	// Calculate the PE authentihash.
	//pe.Authentihash()

	// Calculate the PE checksum.
	pe.Checksum()

	wantDosHeader, _ := cmd.Flags().GetBool("dosheader")
	if wantDosHeader {
		dosHeader, _ := json.Marshal(pe.DosHeader)
		log.Info(prettyPrint(dosHeader))
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
	if wantCLR && pe.CLR != nil {
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
		dosHeader, _ := json.Marshal(pe.DosHeader)
		ntHeader, _ := json.Marshal(pe.NtHeader)
		sectionsHeaders, _ := json.Marshal(pe.Sections)
		log.Info(prettyPrint(dosHeader))
		log.Info(prettyPrint(ntHeader))
		log.Info(prettyPrint(sectionsHeaders))
	}

	if pe.IsEXE() {
		log.Debug("File is Exe")
	}
	if pe.IsDLL() {
		log.Debug("File is DLL")
	}
	if pe.IsDriver() {
		log.Debug("File is Driver")
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
			fmt.Print("You are using version 1.0.4")
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
		log.Info(err)
		os.Exit(1)
	}

}
