.code

EXTERNDEF NtShutdownSystem:PROC

public DbgPrint

DbgPrint proc
	jmp QWORD PTR NtShutdownSystem
DbgPrint endp

end
