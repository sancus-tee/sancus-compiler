#ifndef SM_SUPPORT_H
#define SM_SUPPORT_H

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

#define __PS(name) __sm_##name##_public_start
#define __PE(name) __sm_##name##_public_end
#define __SS(name) __sm_##name##_secret_start
#define __SE(name) __sm_##name##_secret_end

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
    void* ad_end = (char*)ad + ad_len;
    void* body_end = (char*)body + body_len;
    sm_id ret;

    // we use memory constraints for all operands because otherwise LLVM's
    // register allocator messes up and uses some of the clobbered registers
    asm("mov %1, r10\n\t"
        "mov %2, r11\n\t"
        "mov %3, r12\n\t"
        "mov %4, r13\n\t"
        "mov %5, r14\n\t"
        "mov %6, r15\n\t"
        ".word 0x1384\n\t"
        "mov r15, %0"
        : "=m"(ret)
        :"m"(ad), "m"(ad_end),
         "m"(body), "m"(body_end),
         "m"(cipher), "m"(tag)
        : "r10", "r11", "r12", "r13", "r14", "r15");

    return ret;
}

always_inline sm_id sancus_unwrap(const void* ad, size_t ad_len,
                                  const void* cipher, size_t cipher_len,
                                  const void* tag, void* body)
{
    void* ad_end = (char*)ad + ad_len;
    void* cipher_end = (char*)cipher + cipher_len;
    sm_id ret;

    // we use memory constraints for all operands because otherwise LLVM's
    // register allocator messes up and uses some of the clobbered registers
    asm("mov %1, r10\n\t"
        "mov %2, r11\n\t"
        "mov %3, r12\n\t"
        "mov %4, r13\n\t"
        "mov %5, r14\n\t"
        "mov %6, r15\n\t"
        ".word 0x1385\n\t"
        "mov r15, %0"
        : "=m"(ret)
        :"m"(ad), "m"(ad_end),
         "m"(cipher), "m"(cipher_end),
         "m"(body), "m"(tag)
        : "r10", "r11", "r12", "r13", "r14", "r15");

    return ret;
}

always_inline sm_id sancus_tag(const void* body, size_t body_len, void* tag)
{
    return sancus_wrap(body, body_len, NULL, 0, NULL, tag);
}

always_inline sm_id sancus_get_id(void* addr)
{
    sm_id ret;
    asm("mov %1, r15\n\t"
        ".word 0x1386\n\t"
        "mov r15, %0"
        : "=m"(ret)
        : "m"(addr)
        : "r15");
    return ret;
}

always_inline sm_id sancus_get_self_id(void)
{
    void* addr;
    asm("mov r0, %0" : "=m"(addr));
    return sancus_get_id(addr);
}

always_inline sm_id sancus_get_caller_id(void)
{
    sm_id ret;
    asm(".word 0x1387\n\t"
        "mov r15, %0"
        : "=m"(ret));
    return ret;
}

void __unprotected_entry(void);
extern char __unprotected_sp;

#define __ANNOTATE(x) __attribute__((annotate(x)))

#define SM_FUNC(name)  __ANNOTATE("sm:" name)
#define SM_ENTRY(name) __ANNOTATE("sm_entry:" name) __attribute__((noinline, used))
#define SM_DATA(name)  SM_FUNC(name)

#endif

