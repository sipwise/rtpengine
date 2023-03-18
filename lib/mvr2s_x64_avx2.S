#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif

#if defined(__x86_64__)

.global mvr2s_avx2

.text

	# void mvr2s_avx2(float *in, const uint16_t len, int16_t *out);
	# convert float array to int16 array with rounding and int16 saturation
mvr2s_avx2:
	vmovups mask(%rip), %ymm3	# mask for vpermd

	ldmxcsr csr(%rip)	# set "round to nearest"

	mov %rsi, %rax
	and $-8, %al		# 8 samples at a time

	xor %rcx, %rcx
loop:
	cmp %rax, %rcx
	jge remainder

	vmovups (%rdi,%rcx,4), %ymm0	# load, 32-bit size

	# v8_float = {-4, -3.20000005, -1.70000005, -0.5, 0, 38000, -38000, 0},
	#    ->
	# v8_int32 = {-4, -3, -2, 0, 0, 38000, -38000, 0},
	vcvtps2dq %ymm0, %ymm1

	# v8_int32 = {-4, -3, -2, 0, 0, 38000, -38000, 0},
	#    ->
	# v16_int16 = {-4, -3, -2, 0, -4, -3, -2, 0, 0, 32767, -32768, 0, 0, 32767, -32768, 0},
	vpackssdw %ymm1, %ymm1, %ymm0

	# v16_int16 = {-4, -3, -2, 0, -4, -3, -2, 0, 0, 32767, -32768, 0, 0, 32767, -32768, 0},
	#    ->
	# v16_int16 = {-4, -3, -2, 0, 0, 32767, -32768, 0, -4, -3, -4, -3, -4, -3, -4, -3},
	vpermd %ymm0, %ymm3, %ymm1

	# v8_int16 = {-4, -3, -2, 0, 0, 32767, -32768, 0},
	vmovdqu %xmm1, (%rdx,%rcx,2)	# store, 16-bit size

	add $8, %rcx		# 8 samples at a time
	jmp loop

remainder:
	cmp %rsi, %rcx
	jge done

	movss (%rdi,%rcx,4), %xmm0
	vcvtps2dq %xmm0, %xmm1
	vpackssdw %xmm1, %xmm1, %xmm0
	movq %xmm0, %rax
	mov %ax, (%rdx,%rcx,2)

	inc %rcx
	jmp remainder

done:
	ret

.data

mask:
	.byte 0x00, 0x00, 0x00, 0x00
	.byte 0x01, 0x00, 0x00, 0x00
	.byte 0x04, 0x00, 0x00, 0x00
	.byte 0x05, 0x00, 0x00, 0x00
	.byte 0x00, 0x00, 0x00, 0x00
	.byte 0x00, 0x00, 0x00, 0x00
	.byte 0x00, 0x00, 0x00, 0x00
	.byte 0x00, 0x00, 0x00, 0x00

csr:
	.byte 0x80, 0x1f, 0x00, 0x00	# [ IM DM ZM OM UM PM ]

#endif
