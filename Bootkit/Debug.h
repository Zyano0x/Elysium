#pragma once
#include "Pch.h"

#define SLEEP( ms ) \
    Gen->SystemTable->BootServices->Stall( ms * 1000 );

#define INFINITY_LOOP( ) \
    for ( ; ; )

#define SET_BACKGROUND( x ) \
    Gen->SystemTable->ConOut->SetAttribute( Gen->SystemTable->ConOut, x );

#define CLEAR_SCREEN( ) \
    Gen->SystemTable->ConOut->ClearScreen( Gen->SystemTable->ConOut );

#define LOG( text, ... ) \
    Gen->SystemTable->ConOut->OutputString( Gen->SystemTable->ConOut, ( CHAR16* ) text L"\r\n" );

#define Error( text, ... ) \
    LOG( text, ##__VA_ARGS__ ); \
    INFINITY_LOOP( );
