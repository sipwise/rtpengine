#if defined(__linux__) && defined(__ELF__)
.section	.note.GNU-stack,"",%progbits
#endif

#if defined(__x86_64__)

.global s16_mix_in_avx512

.text

# 16 bits in 512 bits = 32 samples at a time
s16_mix_in_avx512:
	mov %rdx, %rax
	and $-32, %al			# 32 samples at a time
	xor %rcx, %rcx
loop:
	cmp %rax, %rcx
	jge remainder
	vmovdqu16 (%rdi,%rcx,2), %zmm0	# 16-bit size
	vpaddsw (%rsi,%rcx,2), %zmm0, %zmm1
	vmovdqu16 %zmm1, (%rdi,%rcx,2)	# 16-bit size
	add $32, %rcx			# 32 samples at a time
	jmp loop
remainder:
	xor %r8, %r8
	xor %r9, %r9
	cmp %rdx, %rcx
	jge done
	mov (%rsi,%rcx,2), %r8w		# 16-bit size
	mov (%rdi,%rcx,2), %r9w		# 16-bit size
	movd %r8, %xmm0
	movd %r9, %xmm1
	paddsw %xmm0, %xmm1
	movd %xmm1, %r8
	mov %r8w, (%rdi,%rcx,2)		# 16-bit size
	inc %rcx
	jmp remainder
done:
	ret

#endif
