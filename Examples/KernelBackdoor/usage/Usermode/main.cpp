#include "pch.h"

extern "C" uint64_t NtShutdownSystem = 0;
extern "C" void DbgPrint(PCSTR Format, ...);

/*!
*
* To make this example work, u should patch NtShutdownSystem with DbgPrint!
*
!*/
int main()
{
    /* Load ntdll */
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    /* Get NtShutdownSystem export */
    NtShutdownSystem = (uint64_t)GetProcAddress(ntdll, "NtShutdownSystem");
    std::cout << "NtShutdownSystem: " << std::hex << NtShutdownSystem << std::endl;

    /* Make a call to redirected syscall */
    DbgPrint("Hi from usermode!");

    std::cout << "Call finished" << std::endl;
    system("pause");
}
