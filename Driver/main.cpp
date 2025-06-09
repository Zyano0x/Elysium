#include "main.h"

void MainThread()
{
	while (true)
	{
		int32_t tid = (int32_t)PsGetCurrentThreadId();
		DbgPrint("Current Thread Address -> %d\n", tid);
	}
}