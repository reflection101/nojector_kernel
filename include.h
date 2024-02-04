//riskuware - alien solutions made by monkeys 👽👾
#include <ntifs.h>

//
// Based relocation types.
//

#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_HIGH                  1
#define IMAGE_REL_BASED_LOW                   2
#define IMAGE_REL_BASED_HIGHLOW               3
#define IMAGE_REL_BASED_HIGHADJ               4
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_5    5
#define IMAGE_REL_BASED_RESERVED              6
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_7    7
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_8    8
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_9    9
#define IMAGE_REL_BASED_DIR64                 10

// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage) (PROBABLY 0xNEMI :skull:)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
typedef unsigned long long DWORD;

PVOID GetModuleBaseAddress(
	PCHAR moduleName,
	HANDLE processId
);

PVOID GetDriverBase(
	LPCSTR module_name
);

NTSTATUS RiskuLovesWritingMemory(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_In_ PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesWritten
);

NTSTATUS RiskuLovesReadingVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_In_ PVOID BaseAddress,
	_Out_ PVOID Buffer,
	_In_ SIZE_T BufferSize,
	_Out_opt_ PSIZE_T NumberOfBytesRead
);

extern "C" NTSTATUS ObReferenceObjectByName(
	__in PUNICODE_STRING ObjectName,
	__in ULONG Attributes,
	__in_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PVOID ParseContext,
	__out PVOID * Object
);

extern "C" PVOID PsGetProcessSectionBaseAddress( 
	PEPROCESS Process 
);

extern "C" NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

extern "C" NTSTATUS ObOpenObjectByName(
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in_opt POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__inout_opt PVOID ParseContext,
	__out PHANDLE Handle
);

extern "C" NTKERNELAPI UCHAR * PsGetProcessImageFileName(
	_In_ PEPROCESS Process
);

extern "C" NTSTATUS ZwQueryDirectoryObject(
	IN HANDLE DirectoryHandle,
	OUT PVOID Buffer,
	IN ULONG BufferLength,
	IN BOOLEAN ReturnSingleEntry,
	IN BOOLEAN RestartScan,
	IN OUT PULONG Context,
	OUT PULONG ReturnLength OPTIONAL
);

extern "C" NTSTATUS ZwQuerySystemInformation(
	ULONG InfoClass,
	PVOID Buffer,
	ULONG Length,
	PULONG ReturnLength
);

extern "C" ULONG RtlWalkFrameChain(
	__out PVOID * Callers,
	__in ULONG 	Count,
	__in ULONG 	Flags
);

extern "C" VOID ExAcquirePushLockExclusiveEx(
	PEX_PUSH_LOCK PushLock,
	ULONG Flags
);

extern "C" VOID ExReleasePushLockExclusiveEx(
	PEX_PUSH_LOCK PushLock,
	ULONG Flags
);

extern "C" NTKERNELAPI
PVOID
NTAPI
RtlFindExportedRoutineByName(
	_In_ PVOID ImageBase,
	_In_ PCCH RoutineName
);

typedef struct _IMAGE_THUNK_DATA64 {
	union {
		ULONGLONG ForwarderString;  // PBYTE 
		ULONGLONG Function;         // PDWORD
		ULONGLONG Ordinal;
		ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
	} u1;
} IMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA64* PIMAGE_THUNK_DATA64;

typedef struct _DEVICE_MAP* PDEVICE_MAP;
typedef PIMAGE_THUNK_DATA64             PIMAGE_THUNK_DATA;

typedef struct _OBJECT_DIRECTORY_ENTRY
{
	_OBJECT_DIRECTORY_ENTRY* ChainLink;
	PVOID Object;
	ULONG HashValue;
} OBJECT_DIRECTORY_ENTRY, * POBJECT_DIRECTORY_ENTRY;

typedef struct _OBJECT_DIRECTORY
{
	POBJECT_DIRECTORY_ENTRY HashBuckets[37];
	EX_PUSH_LOCK Lock;
	PDEVICE_MAP DeviceMap;
	ULONG SessionId;
	PVOID NamespaceEntry;
	ULONG Flags;
} OBJECT_DIRECTORY, * POBJECT_DIRECTORY;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	union {
		DWORD   Characteristics;            // 0 for terminating null import descriptor
		DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
	} DUMMYUNIONNAME;
	DWORD   TimeDateStamp;                  // 0 if not bound,
	// -1 if bound, and real date\time stamp
	//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
	// O.W. date/time stamp of DLL bound to (Old BIND)

	DWORD   ForwarderChain;                 // -1 if no forwarders
	DWORD   Name;
	DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED* PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	unsigned char Reserved1[48];
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved2;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved3;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved4;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	PVOID Reserved5;
	SIZE_T QuotaPagedPoolUsage;
	PVOID Reserved6;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _IMAGE_DOS_HEADER {  // DOS .EXE header
	USHORT e_magic;         // Magic number
	USHORT e_cblp;          // Bytes on last page of file
	USHORT e_cp;            // Pages in file
	USHORT e_crlc;          // Relocations
	USHORT e_cparhdr;       // Size of header in paragraphs
	USHORT e_minalloc;      // Minimum extra paragraphs needed
	USHORT e_maxalloc;      // Maximum extra paragraphs needed
	USHORT e_ss;            // Initial (relative) SS value
	USHORT e_sp;            // Initial SP value
	USHORT e_csum;          // Checksum
	USHORT e_ip;            // Initial IP value
	USHORT e_cs;            // Initial (relative) CS value
	USHORT e_lfarlc;        // File address of relocation table
	USHORT e_ovno;          // Overlay number
	USHORT e_res[4];        // Reserved words
	USHORT e_oemid;         // OEM identifier (for e_oeminfo)
	USHORT e_oeminfo;       // OEM information; e_oemid specific
	USHORT e_res2[10];      // Reserved words
	LONG   e_lfanew;        // File address of new exe header
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	short  Machine;
	short  NumberOfSections;
	unsigned TimeDateStamp;
	unsigned PointerToSymbolTable;
	unsigned NumberOfSymbols;
	short  SizeOfOptionalHeader;
	short  Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _IMAGE_IMPORT_BY_NAME {
	unsigned short/*WORD*/    Hint;
	CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, * PIMAGE_IMPORT_BY_NAME;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;


typedef struct _IMAGE_DATA_DIRECTORY {
	unsigned VirtualAddress;
	unsigned Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	short                 Magic;
	unsigned char                 MajorLinkerVersion;
	unsigned char                 MinorLinkerVersion;
	unsigned                SizeOfCode;
	unsigned                SizeOfInitializedData;
	unsigned                SizeOfUninitializedData;
	unsigned                AddressOfEntryPoint;
	unsigned                BaseOfCode;
	ULONGLONG            ImageBase;
	unsigned                SectionAlignment;
	unsigned                FileAlignment;
	short                 MajorOperatingSystemVersion;
	short                 MinorOperatingSystemVersion;
	short                 MajorImageVersion;
	short                 MinorImageVersion;
	short                 MajorSubsystemVersion;
	short                 MinorSubsystemVersion;
	unsigned                Win32VersionValue;
	unsigned                SizeOfImage;
	unsigned                SizeOfHeaders;
	unsigned                CheckSum;
	short                 Subsystem;
	short                 DllCharacteristics;
	ULONGLONG            SizeOfStackReserve;
	ULONGLONG            SizeOfStackCommit;
	ULONGLONG            SizeOfHeapReserve;
	ULONGLONG            SizeOfHeapCommit;
	unsigned                 LoaderFlags;
	unsigned                NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
	unsigned                   Signature;
	IMAGE_FILE_HEADER       FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
	unsigned char Name[8];
	union {
		unsigned PhysicalAddress;
		unsigned VirtualSize;
	} Misc;
	unsigned VirtualAddress;
	unsigned SizeOfRawData;
	unsigned PointerToRawData;
	unsigned PointerToRelocations;
	unsigned PointerToLinenumbers;
	short  NumberOfRelocations;
	short  NumberOfLinenumbers;
	unsigned Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_BASE_RELOCATION {
	ULONG VirtualAddress;
	ULONG SizeOfBlock;
} IMAGE_BASE_RELOCATION;

typedef IMAGE_BASE_RELOCATION UNALIGNED* PIMAGE_BASE_RELOCATION;
typedef IMAGE_NT_HEADERS64                  IMAGE_NT_HEADERS;//ONLY if x64.. 0xnemi probably on x86 lmfao:skull:
#define WhereDaFirstSectionAt( ntheader ) ((PIMAGE_SECTION_HEADER)        \
    ((ULONG_PTR)(ntheader) +                                            \
     FIELD_OFFSET( IMAGE_NT_HEADERS, OptionalHeader ) +                 \
     ((ntheader))->FileHeader.SizeOfOptionalHeader   \
    ))