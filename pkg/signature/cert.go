package signature

import (
    "fmt"
    "io"
    "os"
)

// ExtractCert extracts the digital signature from a PE file
func ExtractCert(filename string) ([]byte, error) {
    info, err := AnalyzeFile(filename)
    if err != nil {
        return nil, err
    }

    if info.CertLOC == 0 || info.CertSize == 0 {
        return nil, fmt.Errorf("file is not signed")
    }

    file, err := os.OpenFile(filename, os.O_RDONLY, 0)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    _, err = file.Seek(int64(info.CertLOC), io.SeekStart)
    if err != nil {
        return nil, err
    }

    cert := make([]byte, info.CertSize)
    _, err = io.ReadFull(file, cert)
    if err != nil {
        return nil, err
    }

    return cert, nil
}

// WriteCert writes a digital signature to a PE file
func WriteCert(cert []byte, inputFile, outputFile string) error {
    info, err := AnalyzeFile(inputFile)
    if err != nil {
        return err
    }

    if outputFile == "" {
        outputFile = inputFile + "_signed"
    }

    err = CopyFile(inputFile, outputFile)
    if err != nil {
        return err
    }

    file, err := os.OpenFile(outputFile, os.O_RDWR, 0)
    if err != nil {
        return err
    }
    defer file.Close()

    fileInfo, err := file.Stat()
    if err != nil {
        return err
    }
    fileSize := fileInfo.Size()

    // Update certificate table
    _, err = file.Seek(info.CertTableLOC, io.SeekStart)
    if err != nil {
        return err
    }

    err = binary.Write(file, binary.LittleEndian, uint32(fileSize))
    if err != nil {
        return err
    }

    err = binary.Write(file, binary.LittleEndian, uint32(len(cert)))
    if err != nil {
        return err
    }

    // Append certificate
    _, err = file.Seek(0, io.SeekEnd)
    if err != nil {
        return err
    }

    _, err = file.Write(cert)
    return err
}

// RemoveCert removes the digital signature from a PE file
func RemoveCert(inputFile, outputFile string) error {
    info, err := AnalyzeFile(inputFile)
    if err != nil {
        return err
    }

    if info.CertLOC == 0 || info.CertSize == 0 {
        return fmt.Errorf("file is not signed")
    }

    if outputFile == "" {
        outputFile = inputFile + "_nosig"
    }

    err = CopyFile(inputFile, outputFile)
    if err != nil {
        return err
    }

    file, err := os.OpenFile(outputFile, os.O_RDWR, 0)
    if err != nil {
        return err
    }
    defer file.Close()

    // Truncate signature
    err = file.Truncate(int64(info.CertLOC))
    if err != nil {
        return err
    }

    // Zero certificate table
    _, err = file.Seek(info.CertTableLOC, io.SeekStart)
    if err != nil {
        return err
    }

    _, err = file.Write(make([]byte, 8))
    return err
}

