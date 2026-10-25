# CR-39 m.5: rustc 1.99.0 (b940084d7 2026-09-28), aarch64-unknown-linux-gnu

ct_eq_32:
	stp x29, x30, [sp, #-32]!
	stp x20, x19, [sp, #16]
	mov x29, sp
	adrp x8, :got:_RNvNtNtCs_10std_detect6detect5cache5CACHE
	ldr x8, [x8, :got_lo12:_RNvNtNtCs_10std_detect6detect5cache5CACHE]
	ldr x8, [x8]
	cbz x8, .L0
	tbz w8, #8, .L1
	.L2:
	mrs x8, S3_3_C4_C2_5
	tbnz w8, #24, .L1
	mov w8, #16777216
	msr S3_3_C4_C2_5, x8
	ldr x0, [x0]
	ldr x1, [x1]
	bl _RNvXs8_Cs_6subtleShNtB5_14ConstantTimeEq5ct_eqCs_6ct_asm
	mov x8, xzr
	msr S3_3_C4_C2_5, x8
	tst w0, #0xff
	cset w0, ne
	ldp x20, x19, [sp, #16]
	ldp x29, x30, [sp], #32
	ret
	.L0:
	mov x20, x1
	mov x19, x0
	bl _RNvNtNtCs_10std_detect6detect5cache21detect_and_initialize
	mov x1, x20
	mov x8, x0
	mov x0, x19
	tbnz w8, #8, .L2
	.L1:
	ldr x0, [x0]
	ldr x1, [x1]
	bl _RNvXs8_Cs_6subtleShNtB5_14ConstantTimeEq5ct_eqCs_6ct_asm
	tst w0, #0xff
	cset w0, ne
	ldp x20, x19, [sp, #16]
	ldp x29, x30, [sp], #32
	ret

ct_eq_bytes_32:
	stp x29, x30, [sp, #-48]!
	str x21, [sp, #16]
	stp x20, x19, [sp, #32]
	mov x29, sp
	adrp x8, :got:_RNvNtNtCs_10std_detect6detect5cache5CACHE
	ldr x8, [x8, :got_lo12:_RNvNtNtCs_10std_detect6detect5cache5CACHE]
	ldr x8, [x8]
	cbz x8, .L0
	tbz w8, #8, .L1
	.L2:
	mrs x8, S3_3_C4_C2_5
	tbnz w8, #24, .L1
	mov w8, #16777216
	msr S3_3_C4_C2_5, x8
	mov w19, #1
	cmp x2, #32
	b.eq .L3
	.L4:
	mov w0, wzr
	cbz w19, .L5
	b .L6
	.L0:
	mov x20, x1
	mov x21, x2
	mov x19, x0
	bl _RNvNtNtCs_10std_detect6detect5cache21detect_and_initialize
	mov x2, x21
	mov x1, x20
	mov x8, x0
	mov x0, x19
	tbnz w8, #8, .L2
	.L1:
	mov w19, wzr
	cmp x2, #32
	b.ne .L4
	.L3:
	ldr x0, [x0]
	bl _RNvXs8_Cs_6subtleShNtB5_14ConstantTimeEq5ct_eqCs_6ct_asm
	tst w0, #0xff
	cset w0, ne
	cbz w19, .L5
	.L6:
	mov x8, xzr
	msr S3_3_C4_C2_5, x8
	.L5:
	ldp x20, x19, [sp, #32]
	ldr x21, [sp, #16]
	ldp x29, x30, [sp], #48
	ret

_RNvXs8_Cs_6subtleShNtB5_14ConstantTimeEq5ct_eqCs_6ct_asm:
	stp x29, x30, [sp, #-48]!
	stp x22, x21, [sp, #16]
	stp x20, x19, [sp, #32]
	mov x29, sp
	ldrb w8, [x0]
	ldrb w9, [x1]
	mov x20, x0
	mov x19, x1
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #1]
	ldrb w9, [x19, #1]
	mov w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #2]
	ldrb w9, [x19, #2]
	and w22, w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #3]
	ldrb w9, [x19, #3]
	mov w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #4]
	ldrb w9, [x19, #4]
	and w10, w21, w0
	and w22, w22, w10
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #5]
	ldrb w9, [x19, #5]
	mov w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #6]
	ldrb w9, [x19, #6]
	and w21, w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #7]
	ldrb w9, [x19, #7]
	and w10, w21, w0
	and w22, w22, w10
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #8]
	ldrb w9, [x19, #8]
	mov w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #9]
	ldrb w9, [x19, #9]
	and w21, w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #10]
	ldrb w9, [x19, #10]
	and w21, w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #11]
	ldrb w9, [x19, #11]
	and w10, w21, w0
	and w22, w22, w10
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #12]
	ldrb w9, [x19, #12]
	mov w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #13]
	ldrb w9, [x19, #13]
	and w21, w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #14]
	ldrb w9, [x19, #14]
	and w21, w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #15]
	ldrb w9, [x19, #15]
	and w21, w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #16]
	ldrb w9, [x19, #16]
	and w10, w21, w0
	and w22, w22, w10
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #17]
	ldrb w9, [x19, #17]
	mov w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #18]
	ldrb w9, [x19, #18]
	and w21, w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #19]
	ldrb w9, [x19, #19]
	and w21, w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #20]
	ldrb w9, [x19, #20]
	and w21, w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #21]
	ldrb w9, [x19, #21]
	and w21, w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #22]
	ldrb w9, [x19, #22]
	and w10, w21, w0
	and w22, w22, w10
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #23]
	ldrb w9, [x19, #23]
	mov w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #24]
	ldrb w9, [x19, #24]
	and w21, w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #25]
	ldrb w9, [x19, #25]
	and w21, w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #26]
	ldrb w9, [x19, #26]
	and w21, w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #27]
	ldrb w9, [x19, #27]
	and w21, w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #28]
	ldrb w9, [x19, #28]
	and w21, w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #29]
	ldrb w9, [x19, #29]
	and w10, w21, w0
	and w22, w22, w10
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #30]
	ldrb w9, [x19, #30]
	mov w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	ldrb w8, [x20, #31]
	ldrb w9, [x19, #31]
	and w19, w21, w0
	cmp w8, w9
	cset w0, eq
	bl _RINvCs_6subtle9black_boxhECs_6ct_asm
	and w8, w19, w0
	and w8, w22, w8
	and w0, w8, #0x1
	ldp x20, x19, [sp, #32]
	ldp x22, x21, [sp, #16]
	ldp x29, x30, [sp], #48
	b _RINvCs_6subtle9black_boxhECs_6ct_asm

_RINvCs_6subtle9black_boxhECs_6ct_asm:
	sub sp, sp, #16
	strb w0, [sp, #12]
	ldrb w0, [sp, #12]
	add sp, sp, #16
	ret
