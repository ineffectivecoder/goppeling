package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
)

type Section struct {
	Name           string
	VirtualAddress uint32
	VirtualSize    uint32
	PointerToRaw   uint32
	SizeOfRawData  uint32
}

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func readString(data []byte, off int) (string, error) {
	if off < 0 || off >= len(data) {
		return "", errors.New("string offset out of range")
	}
	end := off
	for end < len(data) && data[end] != 0 {
		end++
	}
	return string(data[off:end]), nil
}

func parseSections(data []byte, coffOff int, optionalOff int) ([]Section, error) {
	if coffOff+20 > len(data) {
		return nil, errors.New("truncated COFF header")
	}
	numSections := int(binary.LittleEndian.Uint16(data[coffOff+2 : coffOff+4]))
	sizeOpt := int(binary.LittleEndian.Uint16(data[coffOff+16 : coffOff+18]))
	sectionHeadersOff := optionalOff + sizeOpt
	if sectionHeadersOff+numSections*40 > len(data) {
		return nil, errors.New("truncated section headers")
	}

	sections := make([]Section, 0, numSections)
	for i := 0; i < numSections; i++ {
		off := sectionHeadersOff + i*40
		sec := data[off : off+40]
		nameBytes := sec[0:8]
		name := ""
		for j := 0; j < 8 && nameBytes[j] != 0; j++ {
			name += string(nameBytes[j : j+1])
		}
		s := Section{
			Name:           name,
			VirtualAddress: binary.LittleEndian.Uint32(sec[12:16]),
			VirtualSize:    binary.LittleEndian.Uint32(sec[8:12]),
			PointerToRaw:   binary.LittleEndian.Uint32(sec[20:24]),
			SizeOfRawData:  binary.LittleEndian.Uint32(sec[16:20]),
		}
		sections = append(sections, s)
	}
	return sections, nil
}

func rvaToOffset(data []byte, sections []Section, rva uint32) (int, error) {
	for _, s := range sections {
		start := s.VirtualAddress
		end := s.VirtualAddress + s.VirtualSize
		if rva >= start && rva < end {
			off := int(s.PointerToRaw + (rva - start))
			if off < int(s.PointerToRaw) || off >= int(s.PointerToRaw+s.SizeOfRawData) {
				return 0, errors.New("RVA maps beyond section's SizeOfRawData")
			}
			if off >= len(data) {
				return 0, errors.New("file too small for mapped RVA")
			}
			return off, nil
		}
	}
	return 0, fmt.Errorf("RVA 0x%x did not match any section", rva)
}

func parseDllExport(dllPath string) (map[string]bool, error) {
	fmt.Printf("[+] Parsing DLL Export Table: %s\n", dllPath)
	data, err := readFile(dllPath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	if len(data) < 0x40 || string(data[0:2]) != "MZ" {
		return nil, errors.New("not a PE file")
	}
	peOffset := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if peOffset <= 0 || peOffset >= len(data) {
		return nil, errors.New("invalid PE header offset")
	}
	if peOffset+4 > len(data) || string(data[peOffset:peOffset+4]) != "PE\x00\x00" {
		return nil, errors.New("invalid PE signature")
	}

	coffOff := peOffset + 4
	optionalOff := coffOff + 20
	if optionalOff+2 > len(data) {
		return nil, errors.New("truncated optional header")
	}
	magic := binary.LittleEndian.Uint16(data[optionalOff : optionalOff+2])
	var exportTableRVA uint32
	switch magic {
	case 0x10b:
		exportTableRVA = binary.LittleEndian.Uint32(data[optionalOff+96 : optionalOff+100])
	case 0x20b:
		exportTableRVA = binary.LittleEndian.Uint32(data[optionalOff+112 : optionalOff+116])
	default:
		return nil, fmt.Errorf("unknown optional header magic: 0x%x", magic)
	}

	sections, err := parseSections(data, coffOff, optionalOff)
	if err != nil {
		return nil, err
	}

	exports := make(map[string]bool)
	if exportTableRVA == 0 {
		return exports, nil
	}

	exportOffset, err := rvaToOffset(data, sections, exportTableRVA)
	if err != nil {
		return nil, err
	}
	if exportOffset+40 > len(data) {
		return nil, errors.New("export directory truncated")
	}

	exportDir := data[exportOffset : exportOffset+40]
	numNames := int(binary.LittleEndian.Uint32(exportDir[24:28]))
	addressOfNamesRVA := binary.LittleEndian.Uint32(exportDir[32:36])
	if numNames == 0 {
		return exports, nil
	}
	namesOffset, err := rvaToOffset(data, sections, addressOfNamesRVA)
	if err != nil {
		return nil, err
	}

	for i := 0; i < numNames; i++ {
		entryRvaOff := namesOffset + i*4
		if entryRvaOff+4 > len(data) {
			continue
		}
		nameRVA := binary.LittleEndian.Uint32(data[entryRvaOff : entryRvaOff+4])
		nameOff, err := rvaToOffset(data, sections, nameRVA)
		if err != nil {
			continue
		}
		name, err := readString(data, nameOff)
		if err != nil {
			continue
		}
		exports[name] = true
	}

	return exports, nil
}

func parseExeImport(exePath string) (map[string][]string, map[string]bool, error) {
	fmt.Printf("[+] Parsing EXE Import Table: %s\n", exePath)
	data, err := readFile(exePath)
	if err != nil {
		return nil, nil, fmt.Errorf("read file: %w", err)
	}
	if len(data) < 0x40 || string(data[0:2]) != "MZ" {
		return nil, nil, errors.New("not a PE file")
	}
	peOffset := int(binary.LittleEndian.Uint32(data[0x3C:0x40]))
	if peOffset <= 0 || peOffset >= len(data) {
		return nil, nil, errors.New("invalid PE header offset")
	}
	if peOffset+4 > len(data) || string(data[peOffset:peOffset+4]) != "PE\x00\x00" {
		return nil, nil, errors.New("invalid PE signature")
	}
	coffOff := peOffset + 4
	optionalOff := coffOff + 20
	if optionalOff+2 > len(data) {
		return nil, nil, errors.New("truncated optional header")
	}
	magic := binary.LittleEndian.Uint16(data[optionalOff : optionalOff+2])
	isPE64 := false
	var importTableRVA uint32
	switch magic {
	case 0x10b:
		importTableRVA = binary.LittleEndian.Uint32(data[optionalOff+104 : optionalOff+108])
	case 0x20b:
		importTableRVA = binary.LittleEndian.Uint32(data[optionalOff+120 : optionalOff+124])
		isPE64 = true
	default:
		return nil, nil, fmt.Errorf("unknown optional header magic: 0x%x", magic)
	}

	sections, err := parseSections(data, coffOff, optionalOff)
	if err != nil {
		return nil, nil, err
	}

	importsByDLL := make(map[string][]string)
	importedNames := make(map[string]bool)
	if importTableRVA == 0 {
		return importsByDLL, importedNames, nil
	}

	importOffset, err := rvaToOffset(data, sections, importTableRVA)
	if err != nil {
		return nil, nil, err
	}

	for descIndex := 0; ; descIndex++ {
		descOff := importOffset + descIndex*20
		if descOff+20 > len(data) {
			break
		}
		desc := data[descOff : descOff+20]
		origFirstThunk := binary.LittleEndian.Uint32(desc[0:4])
		nameRVA := binary.LittleEndian.Uint32(desc[12:16])
		firstThunk := binary.LittleEndian.Uint32(desc[16:20])
		if origFirstThunk == 0 && nameRVA == 0 && firstThunk == 0 {
			break
		}

		nameOff, err := rvaToOffset(data, sections, nameRVA)
		if err != nil {
			continue
		}
		dllName, err := readString(data, nameOff)
		if err != nil {
			continue
		}
		dllNameLower := strings.ToLower(dllName)
		if _, ok := importsByDLL[dllNameLower]; !ok {
			importsByDLL[dllNameLower] = []string{}
		}

		thunkRVA := origFirstThunk
		if thunkRVA == 0 {
			thunkRVA = firstThunk
		}
		if thunkRVA == 0 {
			continue
		}
		thunkOff, err := rvaToOffset(data, sections, thunkRVA)
		if err != nil {
			continue
		}
		entrySize := 4
		if isPE64 {
			entrySize = 8
		}

		for idx := 0; ; idx++ {
			entryOff := thunkOff + idx*entrySize
			if entryOff+entrySize > len(data) {
				break
			}
			if isPE64 {
				thunk := binary.LittleEndian.Uint64(data[entryOff : entryOff+8])
				if thunk == 0 {
					break
				}
				const IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
				if thunk&IMAGE_ORDINAL_FLAG64 != 0 {
					importsByDLL[dllNameLower] = append(importsByDLL[dllNameLower], fmt.Sprintf("ordinal:#%d", thunk&^IMAGE_ORDINAL_FLAG64))
				} else {
					funcRVA := uint32(thunk & 0xffffffff)
					funcOff, err := rvaToOffset(data, sections, funcRVA)
					if err != nil {
						continue
					}
					name, err := readString(data, funcOff+2)
					if err != nil {
						continue
					}
					importsByDLL[dllNameLower] = append(importsByDLL[dllNameLower], name)
					importedNames[name] = true
				}
			} else {
				thunk := binary.LittleEndian.Uint32(data[entryOff : entryOff+4])
				if thunk == 0 {
					break
				}
				const IMAGE_ORDINAL_FLAG32 = 0x80000000
				if thunk&IMAGE_ORDINAL_FLAG32 != 0 {
					importsByDLL[dllNameLower] = append(importsByDLL[dllNameLower], fmt.Sprintf("ordinal:#%d", thunk&^IMAGE_ORDINAL_FLAG32))
				} else {
					funcRVA := thunk
					funcOff, err := rvaToOffset(data, sections, funcRVA)
					if err != nil {
						continue
					}
					name, err := readString(data, funcOff+2)
					if err != nil {
						continue
					}
					importsByDLL[dllNameLower] = append(importsByDLL[dllNameLower], name)
					importedNames[name] = true
				}
			}
		}
	}
	return importsByDLL, importedNames, nil
}

func generateGoStub(matches []string, outFile string) error {
	f, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer f.Close()

	fmt.Fprintln(f, "package main")
	for _, name := range matches {
		// sanitize function name to a valid Go identifier (basic)
		safeName := strings.ReplaceAll(name, ".", "_")
		safeName = strings.ReplaceAll(safeName, "-", "_")
		// If name starts with digit, prefix with F
		if len(safeName) > 0 && safeName[0] >= '0' && safeName[0] <= '9' {
			safeName = "F" + safeName
		}
		fmt.Fprintf(f, "//export %s\n", safeName)
		fmt.Fprintf(f, "func %s() {\n", safeName)
		fmt.Fprintln(f, "    // stub function, does nothing")
		fmt.Fprintln(f, "}")
	}
	return nil
}

func main() {
	dllPath := flag.String("dll", "", "Path to DLL to parse exports")
	exePath := flag.String("exe", "", "Path to EXE to parse imports")
	outFile := flag.String("out", "stub_hijack.go", "Output Go file for stubs")
	flag.Parse()

	if *dllPath == "" && *exePath == "" {
		log.Fatalf("Usage: %s [-dll <dllpath>] [-exe <exepath>] [-out <outfile>]", os.Args[0])
	}

	// Both DLL + EXE: compare
	if *dllPath != "" && *exePath != "" {
		exports, err := parseDllExport(*dllPath)
		if err != nil {
			log.Fatalf("parseDllExport: %v", err)
		}
		_, importedNames, err := parseExeImport(*exePath)
		if err != nil {
			log.Fatalf("parseExeImport: %v", err)
		}

		matches := []string{}
		for name := range exports {
			if importedNames[name] {
				matches = append(matches, name)
			}
		}

		if len(matches) == 0 {
			fmt.Println("[+] No matching functions found.")
			return
		}

		sort.Strings(matches)
		fmt.Printf("[+] Generating Go no-op stub file: %s\n", *outFile)
		if err := generateGoStub(matches, *outFile); err != nil {
			log.Fatalf("Failed to generate stub file: %v", err)
		}
		fmt.Printf("[+] Stub file created with %d exported functions.\n", len(matches))

		// print matches at the end

		fmt.Println("[+] Matching functions:")

		for _, m := range matches {
			fmt.Printf("  %s\n", m)
		}
		fmt.Println("[*] Fire up a disassembler or debugger to determine optimal function to hijack based on execution order.")
		fmt.Println("[*] Modify the desired function in the resulting go file to implement your payload.")
		return
	}

	// Only DLL
	if *dllPath != "" && *exePath == "" {
		exports, err := parseDllExport(*dllPath)
		if err != nil {
			log.Fatalf("parseDllExport: %v", err)
		}
		fmt.Printf("[+] DLL exports (%d):\n", len(exports))
		names := make([]string, 0, len(exports))
		for n := range exports {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Printf("  %s\n", n)
		}
		return
	}

	// Only EXE
	if *dllPath == "" && *exePath != "" {
		importsByDLL, _, err := parseExeImport(*exePath)
		if err != nil {
			log.Fatalf("parseExeImport: %v", err)
		}
		dlls := make([]string, 0, len(importsByDLL))
		for d := range importsByDLL {
			dlls = append(dlls, d)
		}
		sort.Strings(dlls)
		for _, d := range dlls {
			fmt.Printf("DLL: %s\n", d)
			funcs := importsByDLL[d]
			sort.Strings(funcs)
			for _, f := range funcs {
				fmt.Printf("  %s\n", f)
			}
		}
		return
	}
}
