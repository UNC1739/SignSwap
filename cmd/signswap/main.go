package main

import (
    "flag"
    "fmt"
    "os"
    "github.com/UNC1739/SignSwap/pkg/signature"
)

func main() {
    var (
        inputFile  = flag.String("i", "", "Input file")
        outputFile = flag.String("o", "", "Output file")
        sigFile    = flag.String("s", "", "Signature file")
        targetFile = flag.String("t", "", "Target file to append signature to")
        rip        = flag.Bool("r", false, "Rip signature from input file")
        check      = flag.Bool("c", false, "Check if file is signed")
        truncate   = flag.Bool("T", false, "Truncate signature")
    )

    flag.Parse()

    if *inputFile == "" && *targetFile == "" {
        flag.Usage()
        os.Exit(1)
    }

    if *inputFile != "" && *targetFile != "" && *sigFile == "" {
        cert, err := signature.ExtractCert(*inputFile)
        if err != nil {
            fmt.Printf("Error copying signature: %v\n", err)
            os.Exit(1)
        }

        err = signature.WriteCert(cert, *targetFile, *outputFile)
        if err != nil {
            fmt.Printf("Error writing certificate: %v\n", err)
            os.Exit(1)
        }
        fmt.Println("Signature copied successfully")
        return
    }

    if *inputFile != "" && *rip {
        cert, err := signature.ExtractCert(*inputFile)
        if err != nil {
            fmt.Printf("Error ripping signature: %v\n", err)
            os.Exit(1)
        }

        outFile := *outputFile
        if outFile == "" {
            outFile = *inputFile + "_sig"
        }

        err = os.WriteFile(outFile, cert, 0644)
        if err != nil {
            fmt.Printf("Error writing signature: %v\n", err)
            os.Exit(1)
        }
        fmt.Printf("Signature ripped to %s\n", outFile)
        return
    }

    if *targetFile != "" && *sigFile != "" {
        cert, err := os.ReadFile(*sigFile)
        if err != nil {
            fmt.Printf("Error reading signature file: %v\n", err)
            os.Exit(1)
        }

        err = signature.WriteCert(cert, *targetFile, *outputFile)
        if err != nil {
            fmt.Printf("Error writing certificate: %v\n", err)
            os.Exit(1)
        }
        fmt.Println("Signature appended successfully")
        return
    }

    if *inputFile != "" && *check {
        signed, err := signature.IsSigned(*inputFile)
        if err != nil {
            fmt.Printf("Error checking signature: %v\n", err)
            os.Exit(1)
        }
        if signed {
            fmt.Println("Input file is signed")
        } else {
            fmt.Println("Input file is not signed")
        }
        return
    }

    if *inputFile != "" && *truncate {
        err := signature.RemoveCert(*inputFile, *outputFile)
        if err != nil {
            fmt.Printf("Error removing signature: %v\n", err)
            os.Exit(1)
        }
        fmt.Println("Signature removed successfully")
        return
    }

    flag.Usage()
    os.Exit(1)
}
