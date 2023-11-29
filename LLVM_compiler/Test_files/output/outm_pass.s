	.text
	.syntax unified
	.eabi_attribute	67, "2.09"	@ Tag_conformance
	.cpu	cortex-m85
	.eabi_attribute	6, 21	@ Tag_CPU_arch
	.eabi_attribute	7, 77	@ Tag_CPU_arch_profile
	.eabi_attribute	8, 0	@ Tag_ARM_ISA_use
	.eabi_attribute	9, 3	@ Tag_THUMB_ISA_use
	.fpu	fpv5-d16
	.eabi_attribute	36, 1	@ Tag_FP_HP_extension
	.eabi_attribute	48, 2	@ Tag_MVE_arch
	.eabi_attribute	46, 1	@ Tag_DSP_extension
	.eabi_attribute	34, 1	@ Tag_CPU_unaligned_access
	.eabi_attribute	50, 2	@ Tag_PAC_extension
	.eabi_attribute	52, 2	@ Tag_BTI_extension
	.eabi_attribute	17, 1	@ Tag_ABI_PCS_GOT_use
	.eabi_attribute	20, 1	@ Tag_ABI_FP_denormal
	.eabi_attribute	21, 1	@ Tag_ABI_FP_exceptions
	.eabi_attribute	23, 3	@ Tag_ABI_FP_number_model
	.eabi_attribute	24, 1	@ Tag_ABI_align_needed
	.eabi_attribute	25, 1	@ Tag_ABI_align_preserved
	.eabi_attribute	38, 1	@ Tag_ABI_FP_16bit_format
	.eabi_attribute	18, 4	@ Tag_ABI_PCS_wchar_t
	.eabi_attribute	14, 0	@ Tag_ABI_PCS_R9_use
	.file	"simple_main.c"
	.globl	factorial                       @ -- Begin function factorial
	.p2align	2
	.type	factorial,%function
	.code	32                              @ @factorial
factorial:
	.fnstart
@ %bb.0:                                @ %entry
	push	{r11, lr}
	mov	r11, sp
	sub	sp, sp, #16
	str	r0, [sp, #8]
	ldr	r0, [sp, #8]
	cmp	r0, #1
	bne	.LBB0_2
	b	.LBB0_1
.LBB0_1:                                @ %if.then
	pacg	r10, pc, r10
	mov	r0, pc
	bl	secure_trace_storage
	ldr	r0, [sp, #8]
	str	r0, [r11, #-4]
	b	.LBB0_3
.LBB0_2:                                @ %if.end
	pacg	r10, pc, r10
	mov	r0, pc
	bl	secure_trace_storage
	ldr	r0, [sp, #8]
	str	r0, [sp, #4]                    @ 4-byte Spill
	sub	r0, r0, #1
	bl	factorial
	ldr	r1, [sp, #4]                    @ 4-byte Reload
	mov	r2, r0
	mul	r0, r1, r2
	str	r0, [r11, #-4]
	b	.LBB0_3
.LBB0_3:                                @ %return
	ldr	r0, [r11, #-4]
	mov	sp, r11
	pop	{r11, lr}
	pacg	r12, lr, r12
	mov	pc, lr
.Lfunc_end0:
	.size	factorial, .Lfunc_end0-factorial
	.fnend
                                        @ -- End function
	.globl	square                          @ -- Begin function square
	.p2align	2
	.type	square,%function
	.code	32                              @ @square
square:
	.fnstart
@ %bb.0:                                @ %entry
	sub	sp, sp, #4
	str	r0, [sp]
	ldr	r1, [sp]
	mul	r0, r1, r1
	add	sp, sp, #4
	pacg	r12, lr, r12
	mov	pc, lr
.Lfunc_end1:
	.size	square, .Lfunc_end1-square
	.fnend
                                        @ -- End function
	.globl	main                            @ -- Begin function main
	.p2align	2
	.type	main,%function
	.code	32                              @ @main
main:
	.fnstart
@ %bb.0:                                @ %entry
	push	{r11, lr}
	mov	r11, sp
	sub	sp, sp, #24
	mov	r0, #0
	str	r0, [r11, #-4]
	ldr	r0, .LCPI2_0
	add	r1, sp, #12
	bl	__isoc99_scanf
	ldr	r0, .LCPI2_1
	bl	printf
	ldr	r0, [sp, #12]
	add	r1, r0, r0, lsr #31
	bic	r1, r1, #1
	sub	r0, r0, r1
	cmp	r0, #1
	bne	.LBB2_2
	b	.LBB2_1
.LBB2_1:                                @ %if.then
	pacg	r10, pc, r10
	mov	r0, pc
	bl	secure_trace_storage
	ldr	r0, .LCPI2_3
	str	r0, [r11, #-8]
	b	.LBB2_3
.LBB2_2:                                @ %if.else
	pacg	r10, pc, r10
	mov	r0, pc
	bl	secure_trace_storage
	ldr	r0, .LCPI2_2
	str	r0, [r11, #-8]
	b	.LBB2_3
.LBB2_3:                                @ %if.end
	ldr	r0, [r11, #-8]
	str	r0, [sp, #8]                    @ 4-byte Spill
	ldr	r0, [sp, #12]
	str	r0, [sp, #4]                    @ 4-byte Spill
	ldr	r0, [sp, #8]
	bl	indirect_secure_trace_storage
	ldr	r0, [sp, #4]                    @ 4-byte Reload
	ldr	r1, [sp, #8]                    @ 4-byte Reload
	mov	lr, pc
	mov	pc, r1
	mov	r0, #0
	mov	sp, r11
	pop	{r11, lr}
	pacg	r12, lr, r12
	mov	pc, lr
	.p2align	2
@ %bb.4:
.LCPI2_0:
	.long	.L.str
.LCPI2_1:
	.long	.L.str.1
.LCPI2_2:
	.long	factorial
.LCPI2_3:
	.long	square
.Lfunc_end2:
	.size	main, .Lfunc_end2-main
	.fnend
                                        @ -- End function
	.type	.L.str,%object                  @ @.str
	.section	.rodata.str1.1,"aMS",%progbits,1
.L.str:
	.asciz	"%d"
	.size	.L.str, 3

	.type	.L.str.1,%object                @ @.str.1
.L.str.1:
	.asciz	"hello world\n"
	.size	.L.str.1, 13

	.ident	"clang version 16.0.0 (https://github.com/llvm/llvm-project.git 435905ecf25ab9da0753931358414164352810f5)"
	.section	".note.GNU-stack","",%progbits
