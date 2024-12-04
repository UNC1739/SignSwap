package signature

import (
    "encoding/binary"
    "fmt"
    "io"
    "os"
)

// AnalyzeFile reads PE file headers and returns structured info
func AnalyzeFile(filename string) (*PEInfo, error) {
    file, err := os.OpenFile(filename, os.O_RDONLY, 0)
    if err != nil {
        return nil, fmt.Errorf("error opening file: %v", err)
    }
    defer file.Close()

    info := &PEInfo{}

    // Read PE header location
    _, err = file.Seek(0x3C, io.SeekStart)
    if err != nil {
        return nil, fmt.Errorf("error seeking to PE header offset: %v", err)
    }

    err = binary.Read(file, binary.LittleEndian, &info.PEHeaderLocation)
    if err != nil {
        return nil, fmt.Errorf("error reading PE header location: %v", err)
    }

    // Calculate COFF start
    info.COFFStart = int64(info.PEHeaderLocation) + 4

    // Read COFF header
    _, err = file.Seek(info.COFFStart, io.SeekStart)
    if err != nil {
        return nil, err
    }

    err = binary.Read(file, binary.LittleEndian, &info.MachineType)
    if err != nil {
        return nil, err
    }

    err = binary.Read(file, binary.LittleEndian, &info.NumberOfSections)
    if err != nil {
        return nil, err
    }

    err = binary.Read(file, binary.LittleEndian, &info.TimeDateStamp)
    if err != nil {
        return nil, err
    }

    // Read size of optional header and characteristics
    _, err = file.Seek(info.COFFStart+16, io.SeekStart)
    if err != nil {
        return nil, err
    }

    err = binary.Read(file, binary.LittleEndian, &info.SizeOfOptionalHeader)
    if err != nil {
        return nil, err
    }

    err = binary.Read(file, binary.LittleEndian, &info.Characteristics)
    if err != nil {
        return nil, err
    }

    info.OptionalHeaderStart = info.COFFStart + 20

    // Read Magic number to determine PE32 vs PE32+
    _, err = file.Seek(info.OptionalHeaderStart, io.SeekStart)
    if err != nil {
        return nil, err
    }

    err = binary.Read(file, binary.LittleEndian, &info.Magic)
    if err != nil {
        return nil, err
    }

    // Get certificate table location
    certTableOffset := info.OptionalHeaderStart + 128
    if info.Magic == 0x20B { // PE32+
        certTableOffset = info.OptionalHeaderStart + 144
    }

    info.CertTableLOC = certTableOffset
    _, err = file.Seek(certTableOffset, io.SeekStart)
    if err != nil {
        return nil, err
    }

    err = binary.Read(file, binary.LittleEndian, &info.CertLOC)
    if err != nil {
        return nil, err
    }

    err = binary.Read(file, binary.LittleEndian, &info.CertSize)
    if err != nil {
        return nil, err
    }

    return info, nil
}

