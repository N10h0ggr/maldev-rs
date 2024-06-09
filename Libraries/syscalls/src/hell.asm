.data
	wSystemCall DWORD 0000h

.code

	SetSSn PROC
			xor eax, eax			; eax = 0
			mov wSystemCall, eax	; wSystemCall = 0					[#]
			mov eax, ecx			; eax = ssn
			mov r8d, eax			; r8d = eax = ssn
			mov wSystemCall, r8d	; wSystemCall = r8d = eax = ssn		[#]
			ret
	SetSSn ENDP


; SetSSn should look like this :
	;SetSSn PROC
	;	mov wSystemCall, 000h
	;	mov wSystemCall, ecx
	;	ret
	;SetSSn ENDP


	run_syscall PROC
			xor r10, r10			; r10 = 0
			mov rax, rcx			; rax = rcx
			mov r10, rax			; r10 = rax	= rcx			[#]
			mov eax, wSystemCall	; eax = ssn					[#]
			jmp Run					; execute 'Run'
			xor eax, eax	; wont run
			xor rcx, rcx	; wont run
			shl r10, 2		; wont run
		Run:
			syscall					;							[#]
			ret						;							[#]
	run_syscall ENDP

end
