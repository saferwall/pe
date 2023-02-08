// Copyright 2018 Saferwall. All rights reserved.
// Use of this source code is governed by Apache v2 license
// license that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"os"
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

	verCmd := flag.NewFlagSet("version", flag.ExitOnError)

	if len(os.Args) < 2 {
		showHelp()
	}

	switch os.Args[1] {

	case "dump":
		dumpCmd.Parse(os.Args[3:])

		cfg := config{
			wantDOSHeader:   *dumpDOSHdr,
			wantRichHeader:  *dumpRichHdr,
			wantNTHeader:    *dumpNTHdr,
			wantCOFF:        *dumpCOFF,
			wantDataDirs:    *dumpDirs,
			wantSections:    *dumpSections,
			wantExport:      *dumpExport,
			wantImport:      *dumpImport,
			wantResource:    *dumpResource,
			wantException:   *dumpException,
			wantCertificate: *dumpCertificate,
			wantReloc:       *dumpReloc,
			wantDebug:       *dumpDebug,
			wantTLS:         *dumpTLS,
			wantLoadCfg:     *dumpLoadCfg,
			wantBoundImp:    *dumpBoundImport,
			wantIAT:         *dumpIAT,
			wantDelayImp:    *dumpDelayedImport,
			wantCLR:         *dumpCLR,
		}

		parse(os.Args[2], cfg)

	case "version":
		verCmd.Parse(os.Args[2:])
		fmt.Println("You are using version 1.3.0")
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
`)
	fmt.Println("\nAvailable sub-commands 'dump' or 'version' subcommands")
	os.Exit(1)
}
