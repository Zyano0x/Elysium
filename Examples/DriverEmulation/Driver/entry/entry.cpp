#include "entry.h"

/* Exported symbol used by the winload.efi to identify mcupdate module */
EXTERN_C __declspec(dllexport) uint64_t McImageInfo = 0x3800000001LL;

/* Success gaget */
EXTERN_C void Gaget();

void ThreadWrapper()
{
	/* Remove callback routine */
	PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);

	/* Mess with the thread here before it reaches main. */
	/* Set priority, CPU affinity etc.		     */

	MainThread();
}

VOID LoadImageNotifyRoutine(_In_opt_ PUNICODE_STRING FullImageName, _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo)
{
	/*!
	*
	* This routine will be invoked while first process is loaded (smss.exe).
	* At this time the kernel itself is initialized, we can create a thread.
	*
	!*/
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
	* 
	* We cant start PsCreateSystemThread here as the kernel is still in the initialization phrase.
	* Internal structures that are need for threads are not initialized yet.
	* But PsSetLoadImageNotifyRoutine works.
	* 
	!*/
	PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
	return STATUS_SUCCESS;
}

/*!
* 
* DriverEntry executions:
* 
*	1st call -> OslpLoadMicrocode      (winload.efi)  [firmware context]
*	2st call -> HalpMcUpdateInitialize (ntoskrnl.exe) [application context]
*	3st call -> HalpMcUpdateInitialize (ntoskrnl.exe) [application context]
*
!*/
NTSTATUS DriverEntry(uint64_t* McpUpdateMicrocodeFunc, int64_t a2)
{
	/* Simulate the original mcupdate.dll interface */

	McpUpdateMicrocodeFunc[0] = (uint64_t)&Gaget;					/* UcpMicrocode    */
	McpUpdateMicrocodeFunc[1] = (uint64_t)&Gaget;					/* UcpMicrocodeEx  */
	McpUpdateMicrocodeFunc[2] = (uint64_t)&Gaget;					/* UcpLock         */
	McpUpdateMicrocodeFunc[3] = (uint64_t)&Gaget;					/* UcpUnlock       */
	McpUpdateMicrocodeFunc[4] = (uint64_t)&Gaget;					/* UcpPostUpdate   */
	McpUpdateMicrocodeFunc[5] = (uint64_t)&HalpMcUpdateExportData;	/* UcpExportData - executed during boot in HalpMcExportAllData (ntoskrnl.exe) */
	McpUpdateMicrocodeFunc[6] = (uint64_t)&Gaget;					/* UcpExportStatus */

	return STATUS_SUCCESS;
}
