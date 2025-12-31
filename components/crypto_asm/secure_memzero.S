    .text
    .align 4
    .global secure_memzero
    .type   secure_memzero, @function

secure_memzero:
    entry   a1, 32
    beqz    a3, .Lzero_done

    movi    a4, 3
    and     a5, a2, a4
    bnez    a5, .Lzero_bytes
    blti    a3, 4, .Lzero_bytes

    movi    a4, 0
.Lzero_words:
    s32i    a4, a2, 0
    addi    a2, a2, 4
    addi    a3, a3, -4
    bgei    a3, 4, .Lzero_words
    beqz    a3, .Lzero_done

.Lzero_bytes:
    movi    a4, 0
.Lzero_byte_loop:
    s8i     a4, a2, 0
    addi    a2, a2, 1
    addi    a3, a3, -1
    bnez    a3, .Lzero_byte_loop

.Lzero_done:
    memw
    retw.n

    .size   secure_memzero, . - secure_memzero
