/*++

Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
    KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
    PURPOSE.

Module Name:

    

Abstract:

   
Environment:

    user mode only

--*/
#pragma once
#ifndef _DETECT_POLL
#define _DETECT_POLL

#define IMPORT_DIRECTORY OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
#define BOUND_DIRECTORY OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]
#define CLR_DIRECTORY OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]
#define IAT_DIRECTORY OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT]

#define offsetof(s,m) (size_t)(unsigned long)&(((s *)0)->m)
 


typedef struct _ImageImportName{ 
	WORD        nHint;
    ULONG       nOrig;
    ULONG       nOrdinal;
    PCHAR       pszOrig;
    PCHAR       pszName;
}ImageImportName;
/*
typedef struct _IMAGE_THUNK_DATA32   
{   
    union   
    {   
        ULONG ForwarderString;      // PUCHAR   
        ULONG Function;             // PULONG   
        ULONG Ordinal;   
        ULONG AddressOfData;        // PIMAGE_IMPORT_BY_NAME   
    } u1;   
} IMAGE_THUNK_DATA32;   
*/
typedef struct _ImageImportFile {

	//LIST_ENTRY				pNextFile;
	struct _ImageImportFile *       pNextFile;
    BOOL                    fByway;

	//LIST_ENTRY				Next1;
    ImageImportName *       pImportNames;
    DWORD                   nImportNames;

    DWORD                   rvaOriginalFirstThunk;//addrsss
    DWORD                   rvaFirstThunk;//addrsss

    DWORD                   nForwarderChain;
    PCHAR                   pszOrig;
    PCHAR                   pszName;
}ImageImportFile;




typedef struct _ImageData{
    PBYTE                   pbData;
    DWORD                   cbData;
    DWORD                   cbAlloc;
}ImageData;

typedef struct _Image{
	DWORD                   dwValidSignature;
    ImageData *             pImageData;               // Read & Write

    HANDLE                  hMap;                     // Read & Write
    PBYTE                   pMap;                     // Read & Write

    DWORD                   nNextFileAddr;            // Write
    DWORD                   nNextVirtAddr;            // Write

    IMAGE_DOS_HEADER        DosHeader;                // Read & Write
    IMAGE_NT_HEADERS        NtHeader;                 // Read & Write
    IMAGE_SECTION_HEADER    SectionHeaders[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];

    DWORD                   nPrePE;
    DWORD                   cbPrePE;
    DWORD                   cbPostPE;

    DWORD                   nPeOffset;
    DWORD                   nSectionsOffset;
    DWORD                   nExtraOffset;
    DWORD                   nFileSize;

    DWORD                   nOutputVirtAddr;
    DWORD                   nOutputVirtSize;
    DWORD                   nOutputFileAddr;

    PBYTE                   pbOutputBuffer;
    DWORD                   cbOutputBuffer;

    ImageImportFile *       pImportFiles;
    DWORD                   nImportFiles;

    BOOL                    fHadDetectPollSection;
} Image;


 

typedef struct _iat_CLR_HEADER
{
    // Header versioning
    ULONG                   cb;
    USHORT                  MajorRuntimeVersion;
    USHORT                  MinorRuntimeVersion;

    // Symbol table and startup information
    IMAGE_DATA_DIRECTORY    MetaData;
    ULONG                   Flags;

    // Followed by the rest of the header.
} iat_CLR_HEADER, *Piat_CLR_HEADER;

#pragma pack(push, 8)
typedef struct _iat_SECTION_HEADER
{
    DWORD       cbHeaderSize;
    DWORD       nSignature;
    DWORD       nDataOffset;
    DWORD       cbDataSize;

    DWORD       nOriginalImportVirtualAddress;
    DWORD       nOriginalImportSize;
    DWORD       nOriginalBoundImportVirtualAddress;
    DWORD       nOriginalBoundImportSize;

    DWORD       nOriginalIatVirtualAddress;
    DWORD       nOriginalIatSize;
    DWORD       nOriginalSizeOfImage;
    DWORD       cbPrePE;

    DWORD       nOriginalClrFlags;
    DWORD       reserved1;
    DWORD       reserved2;
    DWORD       reserved3;

    // Followed by cbPrePE bytes of data.
} iat_SECTION_HEADER, *Piat_SECTION_HEADER;


typedef struct _iat_EXE_RESTORE
{
    ULONG               cb;

    PIMAGE_DOS_HEADER   pidh;
    PIMAGE_NT_HEADERS   pinh;
    PULONG              pclrFlags;
    DWORD               impDirProt;

    IMAGE_DOS_HEADER    idh;
    IMAGE_NT_HEADERS    inh;
    ULONG               clrFlags;
} iat_EXE_RESTORE, *Piat_EXE_RESTORE;


typedef BOOL (CALLBACK *PF_iat_ENUMERATE_EXPORT_CALLBACK)(PVOID pContext,
                                                             ULONG nOrdinal,
                                                             PCHAR pszName,
                                                             PVOID pCode);

 BOOL STDAPI UpdateImports(HANDLE hProcess, LPCSTR *plpDlls, DWORD nDlls);
 BOOL  STDAPI iatEnumerateExports(HMODULE hModule,
                                   PVOID pContext,
                                   PF_iat_ENUMERATE_EXPORT_CALLBACK pfExport);
 int STDAPI test();
extern "C" BOOL ImageRead(HANDLE hFile);

typedef BOOL (WINAPI *Piat_CREATE_PROCESS_ROUTINEA)
    (LPCSTR lpApplicationName,
     LPSTR lpCommandLine,
     LPSECURITY_ATTRIBUTES lpProcessAttributes,
     LPSECURITY_ATTRIBUTES lpThreadAttributes,
     BOOL bInheritHandles,
     DWORD dwCreationFlags,
     LPVOID lpEnvironment,
     LPCSTR lpCurrentDirectory,
     LPSTARTUPINFOA lpStartupInfo,
     LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL (WINAPI *Piat_CREATE_PROCESS_ROUTINEW)
    (LPCWSTR lpApplicationName,
     LPWSTR lpCommandLine,
     LPSECURITY_ATTRIBUTES lpProcessAttributes,
     LPSECURITY_ATTRIBUTES lpThreadAttributes,
     BOOL bInheritHandles,
     DWORD dwCreationFlags,
     LPVOID lpEnvironment,
     LPCWSTR lpCurrentDirectory,
     LPSTARTUPINFOW lpStartupInfo,
     LPPROCESS_INFORMATION lpProcessInformation);

typedef BOOL (CALLBACK *PF_SYMBOL_CALLBACK)(PVOID pContext,                                                         
                                            PCHAR pszSymbol
											);


#endif