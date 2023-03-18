#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif

#if defined(__x86_64__)

.global mvr2s_avx512

.text

	# void mvr2s_avx512(float *in, const uint16_t len, int16_t *out);
	# convert float array to int16 array with rounding and int16 saturation
mvr2s_avx512:
	ldmxcsr csr(%rip)	# set "round to nearest"

	mov %rsi, %rax
	and $-16, %al		# 16 samples at a time

	xor %rcx, %rcx
loop:
	cmp %rax, %rcx
	jge remainder

	vmovups (%rdi,%rcx,4), %zmm0	# load, 32-bit size

	# v16_float = {-2, -2.20000005, -1.70000005, -1.5, 0, 0, 2, 2.20000005, 1.70000005, 1.5, -19187.207, 15405.2158, -4437.91748, -18747.3066, -3701.35034, -19959.6738},
	#    ->
	# v16_int32 = {-2, -2, -2, -2, 0, 0, 2, 2, 2, 2, -19187, 15405, -4438, -18747, -3701, -19960},
	vcvtps2dq %zmm0, %zmm1

	# v16_int32 = {-2, -2, -2, -2, 0, 0, 2, 2, 2, 2, -19187, 15405, -4438, -18747, -3701, -19960},
	#    ->
	# v16_int16 = {-2, -2, -2, -2, 0, 0, 2, 2, 2, 2, -19187, 15405, -4438, -18747, -3701, -19960},
	vpmovsdw %zmm1, %ymm0

	vmovdqu %ymm0, (%rdx,%rcx,2)	# store, 16-bit size

	add $16, %rcx		# 16 samples at a time
	jmp loop

remainder:
	cmp %rsi, %rcx
	jge done

	vmovss (%rdi,%rcx,4), %xmm0
	vcvtps2dq %ymm0, %ymm1
	vpmovsdw %ymm1, %xmm0
	vpextrw $0, %xmm0, (%rdx,%rcx,2)

	inc %rcx
	jmp remainder

done:
	ret

.data

csr:
	.byte 0x80, 0x1f, 0x00, 0x00	# [ IM DM ZM OM UM PM ]

#endif
