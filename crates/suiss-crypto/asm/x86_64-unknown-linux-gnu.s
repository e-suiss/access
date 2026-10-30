# CR-39 m.5: rustc 1.99.0 (b940084d7 2026-09-28), x86_64-unknown-linux-gnu

ct_eq_32:
	pushq %rax
	movq (%rdi), %rdi
	movq (%rsi), %rsi
	callq _RNvXs8_Cs_6subtleShNtB5_14ConstantTimeEq5ct_eqCs_6ct_asm
	testb %al, %al
	setne %al
	popq %rcx
	retq

ct_eq_bytes_32:
	cmpq $32, %rdx
	jne .L0
	pushq %rax
	movq (%rdi), %rdi
	callq _RNvXs8_Cs_6subtleShNtB5_14ConstantTimeEq5ct_eqCs_6ct_asm
	testb %al, %al
	setne %al
	addq $8, %rsp
	retq
	.L0:
	xorl %eax, %eax
	retq

_RNvXs8_Cs_6subtleShNtB5_14ConstantTimeEq5ct_eqCs_6ct_asm:
	pushq %rbp
	pushq %r15
	pushq %r14
	pushq %r13
	pushq %r12
	pushq %rbx
	pushq %rax
	movq %rsi, %rbx
	movq %rdi, %r14
	movzbl (%rdi), %eax
	xorl %edi, %edi
	cmpb (%rsi), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %ebp
	movzbl 1(%r14), %eax
	xorl %edi, %edi
	cmpb 1(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r15d
	andb %bpl, %r15b
	movzbl 2(%r14), %eax
	xorl %edi, %edi
	cmpb 2(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r12d
	movzbl 3(%r14), %eax
	xorl %edi, %edi
	cmpb 3(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %ebp
	andb %r12b, %bpl
	andb %r15b, %bpl
	movzbl 4(%r14), %eax
	xorl %edi, %edi
	cmpb 4(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r15d
	movzbl 5(%r14), %eax
	xorl %edi, %edi
	cmpb 5(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r12d
	andb %r15b, %r12b
	movzbl 6(%r14), %eax
	xorl %edi, %edi
	cmpb 6(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r15d
	andb %r12b, %r15b
	andb %bpl, %r15b
	movzbl 7(%r14), %eax
	xorl %edi, %edi
	cmpb 7(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %ebp
	movzbl 8(%r14), %eax
	xorl %edi, %edi
	cmpb 8(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r12d
	andb %bpl, %r12b
	movzbl 9(%r14), %eax
	xorl %edi, %edi
	cmpb 9(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r13d
	andb %r12b, %r13b
	movzbl 10(%r14), %eax
	xorl %edi, %edi
	cmpb 10(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %ebp
	andb %r13b, %bpl
	andb %r15b, %bpl
	movzbl 11(%r14), %eax
	xorl %edi, %edi
	cmpb 11(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r15d
	movzbl 12(%r14), %eax
	xorl %edi, %edi
	cmpb 12(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r12d
	andb %r15b, %r12b
	movzbl 13(%r14), %eax
	xorl %edi, %edi
	cmpb 13(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r15d
	andb %r12b, %r15b
	movzbl 14(%r14), %eax
	xorl %edi, %edi
	cmpb 14(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r12d
	andb %r15b, %r12b
	movzbl 15(%r14), %eax
	xorl %edi, %edi
	cmpb 15(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r15d
	andb %r12b, %r15b
	andb %bpl, %r15b
	movzbl 16(%r14), %eax
	xorl %edi, %edi
	cmpb 16(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %ebp
	movzbl 17(%r14), %eax
	xorl %edi, %edi
	cmpb 17(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r12d
	andb %bpl, %r12b
	movzbl 18(%r14), %eax
	xorl %edi, %edi
	cmpb 18(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %ebp
	andb %r12b, %bpl
	movzbl 19(%r14), %eax
	xorl %edi, %edi
	cmpb 19(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r12d
	andb %bpl, %r12b
	movzbl 20(%r14), %eax
	xorl %edi, %edi
	cmpb 20(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r13d
	andb %r12b, %r13b
	movzbl 21(%r14), %eax
	xorl %edi, %edi
	cmpb 21(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %ebp
	andb %r13b, %bpl
	andb %r15b, %bpl
	movzbl 22(%r14), %eax
	xorl %edi, %edi
	cmpb 22(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r15d
	movzbl 23(%r14), %eax
	xorl %edi, %edi
	cmpb 23(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r12d
	andb %r15b, %r12b
	movzbl 24(%r14), %eax
	xorl %edi, %edi
	cmpb 24(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r15d
	andb %r12b, %r15b
	movzbl 25(%r14), %eax
	xorl %edi, %edi
	cmpb 25(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r12d
	andb %r15b, %r12b
	movzbl 26(%r14), %eax
	xorl %edi, %edi
	cmpb 26(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r15d
	andb %r12b, %r15b
	movzbl 27(%r14), %eax
	xorl %edi, %edi
	cmpb 27(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r12d
	andb %r15b, %r12b
	movzbl 28(%r14), %eax
	xorl %edi, %edi
	cmpb 28(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r15d
	andb %r12b, %r15b
	andb %bpl, %r15b
	movzbl 29(%r14), %eax
	xorl %edi, %edi
	cmpb 29(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %ebp
	movzbl 30(%r14), %eax
	xorl %edi, %edi
	cmpb 30(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	movl %eax, %r12d
	andb %bpl, %r12b
	movzbl 31(%r14), %eax
	xorl %edi, %edi
	cmpb 31(%rbx), %al
	sete %dil
	callq *_RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip)
	andb %r12b, %al
	andb %r15b, %al
	andb $1, %al
	movzbl %al, %edi
	movq _RINvCs_6subtle9black_boxhECs_6ct_asm@GOTPCREL(%rip), %rax
	addq $8, %rsp
	popq %rbx
	popq %r12
	popq %r13
	popq %r14
	popq %r15
	popq %rbp
	jmpq *%rax

_RINvCs_6subtle9black_boxhECs_6ct_asm:
	movb %dil, -1(%rsp)
	movzbl -1(%rsp), %eax
	retq
