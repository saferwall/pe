# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2021-12-20
### Added
- Add .editorconfig and .vscode config.
- Add github action CI workflow to test the package.
- Add few badges for the README.md to track build status, coverage and code quality.
- Introduce a new API to parse a file from a byte array.
- Parse .net metadata Module table.
- Parse .net metadata stream headers and metadata tables stream header.
- Add cmd/pedumper to illustrate how to use the library.
- Add unit test for relocation, exception, security, symbol, file, nt header, section and helper files.
- Add an option `New()` to customize max of relocations entries and COFF symbols to parse.

### Changed
- Remove uneeded break statements & lowercase error messages and anomalies.
- Make COFF entry in File struct a pointer.
- Remove unsafe pointer usage from resource directory.
- Do not return an error when COFF symbol table is not found.
- License from Apache 2 to MIT.

### Fixed
- Probe for invalid Nt Header offset.
- Fix authenticode hash calculation.
- Compile correctly on 32 bit thnkas to @Max Altgelt.
- COFF symbol table `readASCIIStringAtOffset()` out of bounds exception.
- Probe for optional header section alignment != 0.
- Fix infinite loop in exception unwind code parsing.
- Fix last data directory entry is reserved and must be zero.
- Safe ready of global pointer register

## [1.0.0] - 2021-03-04 (Initial Release)
- Works with PE32/PE32+ file fomat.
- Supports Intel x86/AMD64/ARM7ARM7 Thumb/ARM8-64/IA64/CHPE architectures.
- MS DOS header.
- Rich Header (calculate checksum).
- NT Header (file header + optional header).
- COFF symbol table and string table.
- Sections headers + entropy calculation.
- Data directories:
  - Import Table + ImpHash calculation.
  - Export Table.
  - Resource Table.
  - Exceptions Table.
  - Security Table + Authentihash calculation.
  - Relocations Table.
  - Debug Table (CODEVIEW, POGO, VC FEATURE, REPRO, FPO, EXDLL CHARACTERISTICS debug types).
  - TLS Table.
  - Load Config Directory (SEH, GFID, GIAT, Guard LongJumps, CHPE, Dynamic Value Reloc Table, Enclave Configuration, Volatile Metadata tables).
  - Bound Import Table.
  - Delay Import Table.
  - COM Table (CLR Metadata Header, Metadata Table Streams).
  - Report several anomalies.
