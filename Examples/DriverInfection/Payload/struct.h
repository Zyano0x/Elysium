#pragma once

typedef void VOID;
typedef void* PVOID;
typedef unsigned __int64 ULONG_PTR;

/* Cast as a pointer-wide variable */
#define U_PTR( x )	( ULONG_PTR )( x )

/* Cast as a generic pointer */
#define C_PTR( x )	( PVOID )( x )

/* Place function in a specific order */
#define D_SEC( x )	__pragma( code_seg( push, ".text$" #x ) )
#define E_SEC       __pragma( code_seg( pop ) )

#define TRUE 1

#define EXTERN_C extern "C"

typedef unsigned long long UINT64;
typedef unsigned int       UINT32;
typedef unsigned short     UINT16;
typedef unsigned char      UINT8;

typedef signed long long INT64;
typedef signed int       INT32;
typedef signed short     INT16;
typedef signed char      INT8;

typedef UINT64* PUINT64;
typedef UINT32* PUINT32;
typedef UINT16* PUINT16;
typedef UINT8*  PUINT8;

typedef INT64* PINT64;
typedef INT32* PINT32;
typedef INT16* PINT16;
typedef INT8*  PINT8;

#define IA32_LSTAR 0xC0000082

#define PAGE_SIZE 0x1000
#define PAGE_MASK  (~(PAGE_SIZE - 1))

#define LARGE_PAGE_SIZE 0x200000
#define LARGE_PAGE_MASK  (~(LARGE_PAGE_SIZE - 1))

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE  0x00004550

typedef struct _IMAGE_DOS_HEADER
{
    UINT16 e_magic;
    UINT16 e_cblp;
    UINT16 e_cp;
    UINT16 e_crlc;
    UINT16 e_cparhdr;
    UINT16 e_minalloc;
    UINT16 e_maxalloc;
    UINT16 e_ss;
    UINT16 e_sp;
    UINT16 e_csum;
    UINT16 e_ip;
    UINT16 e_cs;
    UINT16 e_lfarlc;
    UINT16 e_ovno;
    UINT16 e_res[4];
    UINT16 e_oemid;
    UINT16 e_oeminfo;
    UINT16 e_res2[10];
    INT32  e_lfanew;
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER
{
    UINT16 Machine;
    UINT16 NumberOfSections;
    UINT32 TimeDateStamp;
    UINT32 PointerToSymbolTable;
    UINT32 NumberOfSymbols;
    UINT16 SizeOfOptionalHeader;
    UINT16 Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY
{
    UINT32 VirtualAddress;
    UINT32 Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
    UINT16            Magic;
    UINT8             MajorLinkerVersion;
    UINT8             MinorLinkerVersion;
    UINT32            SizeOfCode;
    UINT32            SizeOfInitializedData;
    UINT32            SizeOfUninitializedData;
    UINT32            AddressOfEntryPoint;
    UINT32            BaseOfCode;
    UINT64            ImageBase;
    UINT32            SectionAlignment;
    UINT32            FileAlignment;
    UINT16            MajorOperatingSystemVersion;
    UINT16            MinorOperatingSystemVersion;
    UINT16            MajorImageVersion;
    UINT16            MinorImageVersion;
    UINT16            MajorSubsystemVersion;
    UINT16            MinorSubsystemVersion;
    UINT32            Win32VersionValue;
    UINT32            SizeOfImage;
    UINT32            SizeOfHeaders;
    UINT32            CheckSum;
    UINT16            Subsystem;
    UINT16            DllCharacteristics;
    UINT64            SizeOfStackReserve;
    UINT64            SizeOfStackCommit;
    UINT64            SizeOfHeapReserve;
    UINT64            SizeOfHeapCommit;
    UINT32            LoaderFlags;
    UINT32            NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64
{
    UINT32                  Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_EXPORT_DIRECTORY
{
    UINT32 Characteristics;
    UINT32 TimeDateStamp;
    UINT16 MajorVersion;
    UINT16 MinorVersion;
    UINT32 Name;
    UINT32 Base;
    UINT32 NumberOfFunctions;
    UINT32 NumberOfNames;
    UINT32 AddressOfFunctions;
    UINT32 AddressOfNames;
    UINT32 AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;