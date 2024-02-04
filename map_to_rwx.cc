//riskuware - alien solutions made by monkeys 👽👾
//ud for 5 cpu cycles :fire:
#include "include.h"

//i dont wanna enumerate through each and every process
//to find your target one
//so enable PID viewing in task manager
//and put ur pid there
//will save risku lots of time
//ty good share ^^
#define TARGET_PID 16918

//we need to find it yes we do
//nt header -> section -> filter characteristic to RWX
//i totally did NOT paste this from x64dbg's section filtering routines
//no i did NOT :pray:
//free cripmac btw
//nah but like seriously
//seriously
//free him dawg
ULONG_PTR WhereDaRWXPageAtDawg( PCHAR moduleName )//more like section but risku cant code :(
{
    ULONG_PTR moduleBase = reinterpret_cast< ULONG_PTR >( GetModuleBaseAddress( moduleName, reinterpret_cast< HANDLE >( TARGET_PID ) ) );
    if ( moduleBase == 0 )
        return 0;

    PIMAGE_DOS_HEADER dosHeader = ( PIMAGE_DOS_HEADER ) moduleBase;
    PIMAGE_NT_HEADERS ntHeaders = ( PIMAGE_NT_HEADERS ) ( moduleBase + dosHeader->e_lfanew );
    PIMAGE_SECTION_HEADER sectionHeader = WhereDaFirstSectionAt( ntHeaders );

    for ( USHORT i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++ )
    {
        ULONG characteristics = sectionHeader[i].Characteristics;

        //samueltulach, learn from me
        //stop harcoding SCN image definitions, please
        //thanks sam<3
        //-risku

        //edit: actually i dont wanna include ntimage.h anymore :pray:
        //i will hard code it
        //samuel, i understand the decisinos and the risks u took dawg.
        //dont worry dawg.
        //-risku

        #define PageExecute                0x20000000
        #define PageRead                   0x40000000
        #define PageWrite                  0x80000000

        if ( ( characteristics & PageExecute ) &&
            ( characteristics & PageRead ) &&
            ( characteristics & PageWrite ) )
        {
            return ( ULONG_PTR ) ( moduleBase + sectionHeader[i].VirtualAddress );
        }
    }

    return 0;
}

//We getting banned
//-Jarvis, and zerax
NTSTATUS MmapRoutine( PCHAR moduleName )
{
    NTSTATUS status;
    PEPROCESS targetProcess;
    PVOID targetBaseAddress;
    HANDLE targetProcessHandle;

    status = PsLookupProcessByProcessId( reinterpret_cast< HANDLE >( TARGET_PID ), &targetProcess );
    if ( !NT_SUCCESS( status ) )
        return status;

    //Really unnecessary but WHY NOT
    status = ObOpenObjectByPointer( targetProcess, OBJ_KERNEL_HANDLE, NULL, 0, *PsProcessType, KernelMode, &targetProcessHandle );
    if ( !NT_SUCCESS( status ) )
    {
        ObDereferenceObject( targetProcess );
        return status;
    }

    //PEB meme is unfortunately unalived by EAC :((((((
    //well more like eos version but yeah
    targetBaseAddress = PsGetProcessSectionBaseAddress( targetProcess );
    if ( targetBaseAddress == NULL )
    {
        ZwClose( targetProcessHandle );
        ObDereferenceObject( targetProcess );
        return STATUS_INVALID_PARAMETER;
    }

    ULONG_PTR rwxSection = WhereDaRWXPageAtDawg( moduleName );//Self explanatory you ape
    if ( rwxSection == 0 )
    {
        ZwClose( targetProcessHandle );
        ObDereferenceObject( targetProcess );
        return STATUS_NOT_FOUND;
    }

    HANDLE currentProcessId = PsGetCurrentProcessId( );//we are in a kernel driver remember that risku
    PVOID currentBaseAddress = PsGetProcessSectionBaseAddress( PsGetCurrentProcess( ) );//no __readgsqword HAHAAHAHHAAHAHHAHAHAHha. my bad dawg.

    PVOID remoteImageBase = NULL;
    SIZE_T imageSize = 0;

    status = RiskuLovesReadingVirtualMemory( targetProcessHandle, &currentBaseAddress, &remoteImageBase, sizeof( PVOID ), NULL );
    if ( !NT_SUCCESS( status ) )
    {
        ZwClose( targetProcessHandle );
        ObDereferenceObject( targetProcess );
        return status;
    }

    //Litearlly.... no other way:skull:
    PIMAGE_DOS_HEADER dosHeader = ( PIMAGE_DOS_HEADER ) remoteImageBase;
    PIMAGE_NT_HEADERS ntHeaders = ( PIMAGE_NT_HEADERS ) ( ( ULONG_PTR ) remoteImageBase + dosHeader->e_lfanew );

    imageSize = ntHeaders->OptionalHeader.SizeOfImage;

    PVOID remoteAllocation = NULL;
    //I can NOT wait to get caught by vgk.sys's InfinityHook set in place which catches every single fucking syscall due to ETW
    //Thanks everdox
    //Thanks 0xNemi
    //No thanks itsgamerdoc
    status = ZwAllocateVirtualMemory( targetProcessHandle, &remoteAllocation, 0, &imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );

    if ( !NT_SUCCESS( status ) )
    {
        ZwClose( targetProcessHandle );
        ObDereferenceObject( targetProcess );
        return status;
    }

    //To differ ;)
    PVOID localImageBase = ExAllocatePoolWithTag( NonPagedPoolNx, imageSize, 'rsku' );
    if ( localImageBase == NULL )
    {
        ZwFreeVirtualMemory( targetProcessHandle, &remoteAllocation, &imageSize, MEM_RELEASE );
        ZwClose( targetProcessHandle );
        ObDereferenceObject( targetProcess );
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    //Call this local shellcode allocation
    //I call this local shellcode allocation
    //-Playboi carti, probably
    RtlCopyMemory( localImageBase, currentBaseAddress, imageSize );

    PIMAGE_BASE_RELOCATION relocation = ( PIMAGE_BASE_RELOCATION ) ( ( ULONG_PTR ) localImageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress );
    ULONG_PTR delta = ( ULONG_PTR ) remoteAllocation - ntHeaders->OptionalHeader.ImageBase;

    //Ud ty good share btbd ^^
    //We love relocating through every block manually
    //Why matter, we just add delta to block ptr:pray:
    while ( relocation->VirtualAddress != 0 )
    {
        ULONG count = ( relocation->SizeOfBlock - sizeof( IMAGE_BASE_RELOCATION ) ) / sizeof( USHORT );
        PUSHORT list = ( PUSHORT ) ( ( ULONG_PTR ) relocation + sizeof( IMAGE_BASE_RELOCATION ) );

        for ( ULONG i = 0; i < count; i++ )
        {
            if ( list[i] >> 12 == IMAGE_REL_BASED_HIGHLOW )
            {
                PULONG_PTR ptr = ( PULONG_PTR ) ( ( ULONG_PTR ) localImageBase + ( relocation->VirtualAddress + ( list[i] & 0xFFF ) ) );
                *ptr += delta;
            }
        }

        relocation = ( PIMAGE_BASE_RELOCATION ) ( ( ULONG_PTR ) relocation + relocation->SizeOfBlock );
    }

    //You could THEORETICALLY compare it to the actual allocation
    //Instead of doing delta meme from the remote allocation base to ours
    PVOID remoteEntryPoint = ( PVOID ) ( ( ULONG_PTR ) remoteAllocation + ntHeaders->OptionalHeader.AddressOfEntryPoint );

    status = RiskuLovesWritingMemory( targetProcessHandle, &remoteEntryPoint, &ntHeaders->OptionalHeader.AddressOfEntryPoint, sizeof( PVOID ), NULL );
    if ( !NT_SUCCESS( status ) )
    {
        ExFreePoolWithTag( localImageBase, 'rsku' );
        ZwFreeVirtualMemory( targetProcessHandle, &remoteAllocation, &imageSize, MEM_RELEASE );
        ZwClose( targetProcessHandle );
        ObDereferenceObject( targetProcess );
        return status;
    }

    status = RiskuLovesWritingMemory( targetProcessHandle, &remoteAllocation, &localImageBase, sizeof( PVOID ), NULL );
    if ( !NT_SUCCESS( status ) )
    {
        ExFreePoolWithTag( localImageBase, 'rsku' );
        ZwFreeVirtualMemory( targetProcessHandle, &remoteAllocation, &imageSize, MEM_RELEASE );
        ZwClose( targetProcessHandle );
        ObDereferenceObject( targetProcess );
        return status;
    }

    HANDLE targetThread;
    //Yeah true EAC team can find us since they set NMI on thread core
    //BattlEye is kinda late to the party :skull: he is stuck on APC memes
    //On my todo list i already planning on adding NMI blocker and 
    //APC meme where I leave all APCs on pending
    //just like how I left ItsGamerDoc on read:skull:
    status = PsCreateSystemThread( &targetThread, THREAD_ALL_ACCESS, NULL, targetProcessHandle, NULL, ( PKSTART_ROUTINE ) remoteEntryPoint, NULL );
    if ( !NT_SUCCESS( status ) )
    {
        ExFreePoolWithTag( localImageBase, 'rsku' );
        ZwFreeVirtualMemory( targetProcessHandle, &remoteAllocation, &imageSize, MEM_RELEASE );
        ZwClose( targetProcessHandle );
        ObDereferenceObject( targetProcess );
        return status;
    }

    ZwClose( targetThread );
    ExFreePoolWithTag( localImageBase, 'rsku' );
    ZwFreeVirtualMemory( targetProcessHandle, &remoteAllocation, &imageSize, MEM_RELEASE );
    ZwClose( targetProcessHandle );
    ObDereferenceObject( targetProcess );

    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry( PDRIVER_OBJECT, PUNICODE_STRING )
{
    //Risku says greetings, do you say greetings back sir?
    DbgPrint( "Hi from risku :wave:" );

#ifdef BOOT_AC_MODE
    //Is everdox watching me?
    //Or is it the korean devs over at FACEIT? I truly wonder...
    if ( !GetDriverBase( "vgk.sys" ) || !GetDriverBase( "FACEIT.sys" ) )
    {
        DbgPrint( "You're supposed to map this with your AC open you monkey\n" );
        //Yes, we are not gonna make a thread and wait for your game
        return NTSTATUS( );
    }
#else
    if ( !GetDriverBase( "EasyAntiCheat_EOS.sys" ) || !GetDriverBase( "EasyAntiCheat.sys" ) || !GetDriverBase( "BEDaisy.sys" ) )
    {
        DbgPrint( "You're supposed to map this with your AC open you monkey\n" );
        //Yes, we are not gonna make a thread and wait for your game
        return NTSTATUS( );
    }
#endif

    //Vulnerable RWX dll is DxtoryMM64.dll
    //No i didnt steal it from some random github repo
    //This dll is from DXTory which is literally part of BE,EAC and VANGUARD's overlay whitelisting
    //Also fyi they do not whitelist medal.tv :skull:
    //their dll not even RWX. no use to me i guessd
    //C:\\users\\risku\\Documents\\ValorantMeme\\x64\\Release\\ValorantMeme.dll
    if ( !STATUS_SUCCESS( MmapRoutine( "DxtoryMM64.dll" ) ) )
    {
        DbgPrint( "Welp.. failed to inject :( RIP BOZO" );
        DbgPrint( "Is DXTORY even opened? little APE" );
        return NTSTATUS( );
    }
    return NTSTATUS( );
}