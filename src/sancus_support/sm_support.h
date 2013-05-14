#ifndef SPM_SUPPORT_H
#define SPM_SUPPORT_H

#include <stddef.h>

typedef unsigned sm_id;
typedef unsigned vendor_id;

struct SancusModule
{
    sm_id id;
    vendor_id vendor_id;
    const char* name;
    void* public_start;
    void* public_end;
    void* secret_start;
    void* secret_end;
};

#define __PS(name) __spm_##name##_public_start
#define __PE(name) __spm_##name##_public_end
#define __SS(name) __spm_##name##_secret_start
#define __SE(name) __spm_##name##_secret_end

#define DECLARE_SM(name, vendor_id)                             \
    extern char __PS(name), __PE(name), __SS(name), __SE(name); \
    struct SancusModule name = {0, vendor_id, #name,            \
                                &__PS(name), &__PE(name),       \
                                &__SS(name), &__SE(name)}

int protect_sm(struct SancusModule* sm);

#define always_inline static inline __attribute__((always_inline))

always_inline void unprotect_sm()
{
    asm(".word 0x1380");
}

always_inline sm_id hmac_verify(const void* expected_hmac,
                                struct SancusModule* sm)
{
    sm_id ret;
    asm("mov %1, r14\n\t"
        "mov %2, r15\n\t"
        ".word 0x1382\n\t"
        "mov r15, %0"
        : "=m"(ret)
        : "r"(sm->public_start), "r"(expected_hmac)
        : "r14", "r15");
    return ret;
}

always_inline sm_id hmac_write(void* dst, struct SancusModule* sm)
{
    sm_id ret;
    asm("mov %1, r14\n\t"
        "mov %2, r15\n\t"
        ".word 0x1383\n\t"
        "mov r15, %0"
        : "=m"(ret)
        : "r"(sm->public_start), "r"(dst)
        : "r14", "r15");
    return ret;
}

always_inline sm_id hmac_sign(void* dest, const void* src, size_t n)
{
    sm_id ret;
    asm("mov %1, r13\n\t"
        "mov %2, r14\n\t"
        "mov %3, r15\n\t"
        ".word 0x1384\n\t"
        "mov r15, %0"
        : "=m"(ret)
        : "m"(src), "r"((char*)src + n), "m"(dest)
        : "r13", "r14", "r15");
    return ret;
}

void __unprotected_entry(void);

#define __ANNOTATE(x) __attribute__((annotate(x)))

#define SM_FUNC(name)  __ANNOTATE("spm:" name)
#define SM_ENTRY(name) __ANNOTATE("spm_entry:" name) __attribute__((noinline, used))
#define SM_DATA(name)  SM_FUNC(name)

#endif

