    .text

    .align 4
    .global ct_select32
    .type   ct_select32, @function

ct_select32:
    entry   a1, 32
    neg     a5, a4
    or      a5, a5, a4
    srai    a5, a5, 31
    movi    a6, -1
    xor     a6, a6, a5
    and     a2, a2, a6
    and     a3, a3, a5
    or      a2, a2, a3
    retw.n

    .size   ct_select32, . - ct_select32

    .align 4
    .global ct_select_bytes
    .type   ct_select_bytes, @function

ct_select_bytes:
    entry   a1, 48
    neg     a7, a6
    or      a7, a7, a6
    srai    a7, a7, 31
    movi    a8, -1
    xor     a8, a8, a7
    beqz    a5, .Lselb_done
.Lselb_loop:
    l8ui    a9, a3, 0
    l8ui    a10, a4, 0
    and     a9, a9, a8
    and     a10, a10, a7
    or      a9, a9, a10
    s8i     a9, a2, 0
    addi    a2, a2, 1
    addi    a3, a3, 1
    addi    a4, a4, 1
    addi    a5, a5, -1
    bnez    a5, .Lselb_loop
.Lselb_done:
    retw.n

    .size   ct_select_bytes, . - ct_select_bytes

    .align 4
    .global ct_cswap32
    .type   ct_cswap32, @function

ct_cswap32:
    entry   a1, 32
    l32i    a5, a2, 0
    l32i    a6, a3, 0
    neg     a7, a4
    or      a7, a7, a4
    srai    a7, a7, 31
    xor     a8, a5, a6
    and     a8, a8, a7
    xor     a5, a5, a8
    xor     a6, a6, a8
    s32i    a5, a2, 0
    s32i    a6, a3, 0
    retw.n

    .size   ct_cswap32, . - ct_cswap32
