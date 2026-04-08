// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
)

type config struct {
	wantDOSHeader   bool
	wantRichHeader  bool
	wantNTHeader    bool
	wantCOFF        bool
	wantDataDirs    bool
	wantSections    bool
	wantExport      bool
	wantImport      bool
	wantResource    bool
	wantException   bool
	wantCertificate bool
	wantReloc       bool
	wantDebug       bool
	wantTLS         bool
	wantLoadCfg     bool
	wantBoundImp    bool
	wantIAT         bool
	wantDelayImp    bool
	wantCLR         bool
}

func main() {

	dumpCmd := flag.NewFlagSet("dump", flag.ExitOnError)
	dumpDOSHdr := dumpCmd.Bool("dosheader", false, "Dump DOS header")
	dumpRichHdr := dumpCmd.Bool("richheader", false, "Dump Rich header")
	dumpNTHdr := dumpCmd.Bool("ntheader", false, "Dump NT header")
	dumpCOFF := dumpCmd.Bool("coff", false, "Dump COFF symbols")
	dumpDirs := dumpCmd.Bool("directories", false, "Dump data directories")
	dumpSections := dumpCmd.Bool("sections", false, "Dump sections")
	dumpExport := dumpCmd.Bool("export", false, "Dump export table")
	dumpImport := dumpCmd.Bool("import", false, "Dump import table")
	dumpResource := dumpCmd.Bool("resource", false, "Dump resource table")
	dumpException := dumpCmd.Bool("exception", false, "Dump exception table")
	dumpCertificate := dumpCmd.Bool("cert", false, "Dump certificate directory")
	dumpReloc := dumpCmd.Bool("reloc", false, "Dump relocation table")
	dumpDebug := dumpCmd.Bool("debug", false, "Dump debug infos")
	dumpTLS := dumpCmd.Bool("tls", false, "Dump TLS")
	dumpLoadCfg := dumpCmd.Bool("loadconfig", false, "Dump load configuration table")
	dumpBoundImport := dumpCmd.Bool("bound", false, "Dump bound import table")
	dumpIAT := dumpCmd.Bool("iat", false, "Dump IAT")
	dumpDelayedImport := dumpCmd.Bool("delay", false, "Dump delay import descriptor")
	dumpCLR := dumpCmd.Bool("clr", false, "Dump CLR")

	dumpCmd.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: pedumper dump [flags] <file-or-directory>\n\nFlags:\n")
		dumpCmd.PrintDefaults()
	}

	if len(os.Args) < 2 {
		showHelp()
	}

	switch os.Args[1] {

	case "dump":
		dumpCmd.Parse(os.Args[2:])

		args := dumpCmd.Args()
		if len(args) == 0 {
			fmt.Fprintf(os.Stderr, "Error: missing file or directory path\n\n")
			dumpCmd.Usage()
			os.Exit(1)
		}
		filePath := args[0]

		// If no flags are specified, dump everything.
		noFlagsSet := true
		dumpCmd.Visit(func(f *flag.Flag) { noFlagsSet = false })

		cfg := config{
			wantDOSHeader:   *dumpDOSHdr || noFlagsSet,
			wantRichHeader:  *dumpRichHdr || noFlagsSet,
			wantNTHeader:    *dumpNTHdr || noFlagsSet,
			wantCOFF:        *dumpCOFF || noFlagsSet,
			wantDataDirs:    *dumpDirs || noFlagsSet,
			wantSections:    *dumpSections || noFlagsSet,
			wantExport:      *dumpExport || noFlagsSet,
			wantImport:      *dumpImport || noFlagsSet,
			wantResource:    *dumpResource || noFlagsSet,
			wantException:   *dumpException || noFlagsSet,
			wantCertificate: *dumpCertificate || noFlagsSet,
			wantReloc:       *dumpReloc || noFlagsSet,
			wantDebug:       *dumpDebug || noFlagsSet,
			wantTLS:         *dumpTLS || noFlagsSet,
			wantLoadCfg:     *dumpLoadCfg || noFlagsSet,
			wantBoundImp:    *dumpBoundImport || noFlagsSet,
			wantIAT:         *dumpIAT || noFlagsSet,
			wantDelayImp:    *dumpDelayedImport || noFlagsSet,
			wantCLR:         *dumpCLR || noFlagsSet,
		}

		// Start as many workers you want, default to cpu count -1.
		numWorkers := runtime.GOMAXPROCS(runtime.NumCPU() - 1)
		for w := 1; w <= numWorkers; w++ {
			go loopFilesWorker(cfg)
		}

		if !isDirectory(filePath) {
			// Input path in a single file.
			parsePE(filePath, cfg)
		} else {
			// Input path in a directory.
			LoopDirsFiles(filePath)
			wg.Wait()
		}

	case "version":
		fmt.Println("You are using version 1.6.0")
	default:
		showHelp()
	}
}

func showHelp() {
	fmt.Print(
		`
╔═╗╔═╗  ┌─┐┌─┐┬─┐┌─┐┌─┐┬─┐
╠═╝║╣   ├─┘├─┤├┬┘└─┐├┤ ├┬┘
╩  ╚═╝  ┴  ┴ ┴┴└─└─┘└─┘┴└─

A PE-Parser built for speed and malware-analysis in mind.
Brought to you by Saferwall (c) 2018 MIT

Usage: pedumper <command> [options]

Commands:
  dump [flags] <file-or-directory>    Parse and dump PE file information
  version                             Show version information

Run 'pedumper dump -help' for dump flags.
`)

	os.Exit(1)
}
