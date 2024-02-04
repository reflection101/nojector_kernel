//riskuware - alien solutions made by monkeys 👽👾

#include "include.h"
NTSTATUS RiskuLovesReadingVirtualMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _Out_ PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesRead
)
{
    NTSTATUS status;
    PSIZE_T ioStatus{};

    if ( ProcessHandle == NULL || BaseAddress == NULL || Buffer == NULL || BufferSize == 0 ) {
        return STATUS_INVALID_PARAMETER;
    }

    PEPROCESS Meme;
    PsLookupProcessByProcessId( ProcessHandle, &Meme );
    status = MmCopyVirtualMemory(
        PsGetCurrentProcess( ),      // Source process (current process)
        BaseAddress,                 // Source address
        Meme,                        // Destination process
        Buffer,                      // Destination buffer
        BufferSize,                  // Number of bytes to copy
        KernelMode,                  // Requested access mode (KernelMode for reading)
        ioStatus                     // IO status block
    );

    //if ( NT_SUCCESS( status ) && NumberOfBytesWritten != NULL ) {
    //    *NumberOfBytesWritten = ( SIZE_T ) ioStatus.Information;
    //}

    return status;
}

NTSTATUS RiskuLovesWritingMemory(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ PVOID Buffer,
    _In_ SIZE_T BufferSize,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
)
{
    NTSTATUS status;
    PSIZE_T ioStatus{};

    if ( ProcessHandle == NULL || BaseAddress == NULL || Buffer == NULL || BufferSize == 0 ) {
        return STATUS_INVALID_PARAMETER;
    }

    PEPROCESS Meme;
    PsLookupProcessByProcessId( ProcessHandle, &Meme );
    status = MmCopyVirtualMemory(
        PsGetCurrentProcess( ),      // Source process (current process)
        Buffer,                     // Source buffer
        Meme,  // Destination process
        BaseAddress,                // Destination address
        BufferSize,                 // Number of bytes to copy
        KernelMode,                 // Requested access mode (KernelMode for writing)
        ioStatus                   // IO status block
    );

    //if ( NT_SUCCESS( status ) && NumberOfBytesWritten != NULL ) {
    //    *NumberOfBytesWritten = ( SIZE_T ) ioStatus.Information;
    //}

    return status;
}

PVOID GetModuleBaseAddress( 
    PCHAR moduleName, 
    HANDLE processId 
)
{
    NTSTATUS status;
    PEPROCESS targetProcess = NULL;
    PVOID baseAddress = NULL;

    //Get a pointer to the target process by its Process ID
    //Its like 1000x time we did this but its aight
    status = PsLookupProcessByProcessId( processId, &targetProcess );
    if ( !NT_SUCCESS( status ) ) {
        DbgPrint( "PsLookupProcessByProcessId had one mission and he failed\nBefore dying he told me%08X\n-Probably james bond\n", status );
        return NULL;
    }

    //Enumerate loaded modules in the target process
    ULONG bufferSize = 0;
    PRTL_PROCESS_MODULES modulesInfo = NULL;

    status = ZwQuerySystemInformation(
        SystemModuleInformation,
        NULL,
        0,
        &bufferSize
    );

    modulesInfo = ( PRTL_PROCESS_MODULES ) ExAllocatePoolWithTag(
        NonPagedPool,
        bufferSize,
        'rsku'
    );

    status = ZwQuerySystemInformation(
        SystemModuleInformation,
        modulesInfo,
        bufferSize,
        NULL
    );

    //Iterate through the loaded modules to find the target module
    //Just like how ItsGamerDoc is absolutely not going to go to vanguard panel and unban me
    for ( ULONG i = 0; i < modulesInfo->NumberOfModules; i++ ) {
        if ( strstr( ( PCHAR ) modulesInfo->Modules[i].FullPathName, moduleName ) ) {
            baseAddress = modulesInfo->Modules[i].ImageBase;
            break;
        }
    }

    ExFreePoolWithTag( modulesInfo, 'rsku' );
    ObDereferenceObject( targetProcess );

    return baseAddress;
}

PVOID GetDriverBase(
    LPCSTR module_name
)
{
    ULONG bytes{};
    NTSTATUS status = ZwQuerySystemInformation(
        SystemModuleInformation,
        NULL,
        bytes,
        &bytes
    );
    if ( !bytes )
        return NULL;
    PRTL_PROCESS_MODULES modules =
        ( PRTL_PROCESS_MODULES ) ExAllocatePoolWithTag( NonPagedPool, bytes, 'rsku' );

    if ( modules )
    {
        status = ZwQuerySystemInformation(
            SystemModuleInformation,
            modules,
            bytes,
            &bytes
        );

        if ( !NT_SUCCESS( status ) )
        {
            ExFreePoolWithTag( modules, 'rsku' );
            return NULL;
        }

        PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
        PVOID module_base{}, module_size{};
        for ( ULONG i = 0; i < modules->NumberOfModules; i++ )
        {
            if ( strcmp( reinterpret_cast< char* >( module[i].FullPathName + module[i].OffsetToFileName ), module_name ) == 0 )
            {
                module_base = module[i].ImageBase;
                module_size = ( PVOID ) module[i].ImageSize;
                break;
            }
        }
        ExFreePoolWithTag( modules, 'rsku' );
        return module_base;
    }
    return NULL;
}