#include "sm_support.h"

int protect_sm(struct SancusModule* sm)
{
    asm("mov %1, r11\n\t"
        "mov %2, r12\n\t"
        "mov %3, r13\n\t"
        "mov %4, r14\n\t"
        "mov %5, r15\n\t"
        ".word 0x1381\n\t"
        "mov r15, %0"
        : "=m"(sm->id)
        : "m"(sm->vendor_id),
          "m"(sm->public_start), "m"(sm->public_end),
          "m"(sm->secret_start), "m"(sm->secret_end)
        : "r11", "r12", "r13", "r14", "r15");

    return sm->id != 0;
}

