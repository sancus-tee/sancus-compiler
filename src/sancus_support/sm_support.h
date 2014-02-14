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

int sancus_enable(struct SancusModule* sm);

#define always_inline static inline __attribute__((always_inline))

always_inline void sancus_disable()
{
    asm(".word 0x1380");
}

always_inline sm_id sancus_verify(const void* expected_tag,
                                  struct SancusModule* sm)
{
    sm_id ret;
    asm("mov %1, r14\n\t"
        "mov %2, r15\n\t"
        ".word 0x1382\n\t"
        "mov r15, %0"
        : "=m"(ret)
        : "r"(sm->public_start), "r"(expected_tag)
        : "r14", "r15");
    return ret;
}

always_inline sm_id sancus_verify_caller(const void* expected_tag)
{
    sm_id ret;
    asm("mov %1, r15\n\t"
        ".word 0x1383\n\t"
        "mov r15, %0"
        : "=m"(ret)
        : "r"(expected_tag)
        : "r15");
    return ret;
}

always_inline sm_id sancus_wrap(const void* ad, size_t ad_len,
                                const void* body, size_t body_len,
                                void* cipher, void* tag)
{
    sm_id ret;
    asm("mov %1, r10\n\t"
        "mov %2, r11\n\t"
        "mov %3, r12\n\t"
        "mov %4, r13\n\t"
        "mov %5, r14\n\t"
        "mov %6, r15\n\t"
        ".word 0x1384\n\t"
        "mov r15, %0"
        : "=m"(ret)
        :"m"(ad), "r"((char*)ad + ad_len),
         "m"(body), "r"((char*)body + ad_len),
         "m"(cipher), "m"(tag)
        : "r10", "r11", "r12", "r13", "r14", "r15");
    return ret;
}

always_inline sm_id sancus_unwrap(const void* ad, size_t ad_len,
                                  const void* cipher, size_t cipher_len,
                                  const void* tag, void* body)
{
    sm_id ret;
    asm("mov %1, r10\n\t"
        "mov %2, r11\n\t"
        "mov %3, r12\n\t"
        "mov %4, r13\n\t"
        "mov %5, r14\n\t"
        "mov %6, r15\n\t"
        ".word 0x1385\n\t"
        "mov r15, %0"
        : "=m"(ret)
        :"m"(ad), "r"((char*)ad + ad_len),
         "m"(cipher), "r"((char*)cipher + cipher_len),
         "m"(body), "m"(tag)
        : "r10", "r11", "r12", "r13", "r14", "r15");
    return ret;
}

void __unprotected_entry(void);

#define __ANNOTATE(x) __attribute__((annotate(x)))

#define SM_FUNC(name)  __ANNOTATE("spm:" name)
#define SM_ENTRY(name) __ANNOTATE("spm_entry:" name) __attribute__((noinline, used))
#define SM_DATA(name)  SM_FUNC(name)

#endif

