    .text
    .align 4
    .global ct_compare
    .type   ct_compare, @function

ct_compare:
    entry   a1, 32
    movi    a5, 0
    beqz    a4, .Lcmp_done

.Lcmp_loop:
    l8ui    a6, a2, 0
    l8ui    a7, a3, 0
    xor     a6, a6, a7
    or      a5, a5, a6
    addi    a2, a2, 1
    addi    a3, a3, 1
    addi    a4, a4, -1
    bnez    a4, .Lcmp_loop

.Lcmp_done:
    mov     a2, a5
    retw.n

    .size   ct_compare, . - ct_compare

    .align 4
    .global ct_is_zero
    .type   ct_is_zero, @function

ct_is_zero:
    entry   a1, 32
    movi    a4, 0
    beqz    a3, .Lisz_done

.Lisz_loop:
    l8ui    a5, a2, 0
    or      a4, a4, a5
    addi    a2, a2, 1
    addi    a3, a3, -1
    bnez    a3, .Lisz_loop

.Lisz_done:
    neg     a5, a4
    or      a5, a5, a4
    srai    a5, a5, 31
    movi    a2, 1
    add     a2, a2, a5
    retw.n

    .size   ct_is_zero, . - ct_is_zero
