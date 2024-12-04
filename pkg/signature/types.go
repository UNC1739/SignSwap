package signature

type PEInfo struct {
    Buffer                int64
    PEHeaderLocation     uint32
    COFFStart            int64
    MachineType         uint16
    NumberOfSections    uint16
    TimeDateStamp       uint32
    SizeOfOptionalHeader uint16
    Characteristics     uint16
    OptionalHeaderStart int64
    Magic               uint16
    AddressOfEntryPoint uint32
    ImageBase          uint64
    SectionAlignment   uint32
    FileAlignment      uint32
    SizeOfImage       uint32
    SizeOfHeaders     uint32
    CheckSum          uint32
    Subsystem         uint16
    DllCharacteristics uint16
    CertTableLOC      int64
    CertLOC           uint32
    CertSize          uint32
}

