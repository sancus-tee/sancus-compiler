#include "spm-support.h"

int protect_spm(struct Spm* spm)
{
    asm("mov %1, r11\n\t"
        "mov %2, r12\n\t"
        "mov %3, r13\n\t"
        "mov %4, r14\n\t"
        "mov %5, r15\n\t"
        ".word 0x1381\n\t"
        "mov r15, %0"
        : "=m"(spm->id)
        : "m"(spm->vendor_id),
          "m"(spm->public_start), "m"(spm->public_end),
          "m"(spm->secret_start), "m"(spm->secret_end)
        : "r11", "r12", "r13", "r14", "r15");

    return spm->id != 0;
}

