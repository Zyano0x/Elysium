#include "utils.h"

UINT32 Strcmp(const char* s1, const char* s2)
{
	while (*s1 && (*s1 == *s2))
	{
		s1++;
		s2++;
	}
	return *(unsigned char*)s1 - *(unsigned char*)s2;
}

UINT64 GetImageBase( PUINT64 Address )
{
	UINT64 Page = U_PTR( Address ) & PAGE_MASK;

	do {
		UINT16 Value = *( PUINT16 )Page;

		if ( Value == IMAGE_DOS_SIGNATURE )
		{
			return Page;
		}

		Page -= PAGE_SIZE;
	} while ( Page != 0 );

	return Page;
}

UINT64 GetKernelBase()
{
	UINT64 Entry = __readmsr( IA32_LSTAR ) & LARGE_PAGE_MASK;

	do {
		UINT16 Value = *( PUINT16 )Entry;

		if ( Value == IMAGE_DOS_SIGNATURE ) 
		{
			return Entry;
		}
		Entry -= LARGE_PAGE_SIZE;
	} while ( Entry != 0 );

	return 0;
}

UINT64 GetExportAddress( UINT64 BaseAddress, const char* FunctionName )
{
	PIMAGE_DOS_HEADER		Dos = C_PTR( BaseAddress );
	PIMAGE_NT_HEADERS64		Nt  = C_PTR( BaseAddress  + Dos->e_lfanew );
	PIMAGE_EXPORT_DIRECTORY Exp = C_PTR( BaseAddress + Nt->OptionalHeader.DataDirectory->VirtualAddress );
	
	UINT64 Addresslist		 = BaseAddress + Exp->AddressOfFunctions;
	UINT64 NameList			 = BaseAddress + Exp->AddressOfNames;
	UINT64 NameOrdinalsList	 = BaseAddress + Exp->AddressOfNameOrdinals;

	for ( UINT32 i = 0; i < Exp->NumberOfNames; ++i )
	{
		UINT64 NameAddressRva = NameList + ( i * sizeof( UINT32 ) );
		UINT64 NameAddr = BaseAddress + *( PUINT32 )NameAddressRva;
		char* Name = (char*)(NameAddr);

		if ( Strcmp( Name, FunctionName ) == 0 )
		{
			UINT64 OrdinalAddress = NameOrdinalsList + ( i * sizeof( UINT16 ) );
			UINT16 ordinal = *( PUINT16 )OrdinalAddress;

			UINT64 FunctionAddressRva = Addresslist + ( ordinal * sizeof( UINT32 ) );
			UINT64 FunctionAddress = BaseAddress + *( PUINT32 )FunctionAddressRva;

			return FunctionAddress;
		}
	}

	return 0;
}