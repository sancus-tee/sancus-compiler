#ifndef SM_SUPPORT_H
#define SM_SUPPORT_H

#include <stddef.h>

/**
 * Type used to represent the internal ID of an SM assigned by Sancus.
 *
 * Note that 0 is an invalid ID so it is often used to indicate an error
 * condition.
 */
typedef unsigned sm_id;

/**
 * Type used to represent vendor IDs.
 */
typedef unsigned vendor_id;

/**
 * Structure containing all the relevant information of a Sancus module.
 *
 * Note that #id will only be correct after a call to sancus_enable().
 */
struct SancusModule
{
    sm_id id;               ///< Sancus ID.
    vendor_id vendor_id;    ///< ID of the vendor of this module.
    const char* name;       ///< Name of this module.
    void* public_start;     ///< Start address of the public section
    void* public_end;       ///< End address of the public section
    void* secret_start;     ///< Start address of the secret section
    void* secret_end;       ///< End address of the secret section
};

#define __PS(name) __sm_##name##_public_start
#define __PE(name) __sm_##name##_public_end
#define __SS(name) __sm_##name##_secret_start
#define __SE(name) __sm_##name##_secret_end

/**
 * This macro can be used to declare a SancusModule structure.
 *
 * Every Sancus module should be declared once (and only once) in the global
 * scope using this macro.
 *
 * @param name      Should be the same as the argument passed to the SM_ENTRY(),
 *                  SM_FUNC() and SM_DATA() macros but without quotation marks.
 * @param vendor_id The ID of the module's vendor.
 */
#define DECLARE_SM(name, vendor_id)                             \
    extern char __PS(name), __PE(name), __SS(name), __SE(name); \
    struct SancusModule name = {0, vendor_id, #name,            \
                                &__PS(name), &__PE(name),       \
                                &__SS(name), &__SE(name)}

/**
 * Enables the protection of the given module.
 *
 * A minimal working example of enabling a Sancus module:
 * @code
 * void SM_ENTRY("mod") a_module_entry(void) {...}
 * DECLARE_SM(mod, 1234);
 * int main(void)
 * {
 *     sancus_enable(&mod);
 *     ...
 * }
 * @endcode
 *
 * @param sm Pointer to a SancusModule to enable. This is typically created by
 *           taking the address of the name defined by DECLARE_SM().
 *
 * @return   A true value iff the protection was successfully enabled.
 */
int sancus_enable(struct SancusModule* sm);

#define always_inline static inline __attribute__((always_inline))

/**
 * Disable the protection of the calling module.
 */
always_inline void sancus_disable()
{
    asm(".word 0x1380");
}

/**
 * Verify the correctness of a module.
 *
 * The correctness of a module is verified by calculating a MAC of the layout
 * of the module described by @p sm and comparing it with the MAC given by
 * @p expected_tag.
 *
 * Note that this function normally should not be called directly; the compiler
 * will insert verification code on inter-module calls.
 */
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

/**
 * Verify the correctness of the calling module.
 *
 * Correctness is defined as with sancus_verify(). See sancus_get_caller_id()
 * for the definition of the calling module.
 */
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

/**
 * Wrap a message using the Sancus authenticated encryption features.
 *
 * @p body_len bytes of data starting at @p body are wrapped using the key of
 * the current module using @p ad_len of associated data starting at @p ad. The
 * resulting cipher text is written to @p cipher (make sure there is a buffer
 * available of at least @p body_len bytes) and the MAC to @p tag (the needed
 * buffer size depends of the amount of security bits the Sancus core has been
 * synthesized with).
 */
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

/**
 * Unwrap a message using the Sancus authenticated encryption features.
 *
 * See sancus_wrap() for an explanation of the parameters.
 */
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

/**
 * The same as sancus_wrap() but only produces the MAC of the message.
 */
always_inline sm_id sancus_tag(const void* body, size_t body_len, void* tag)
{
    return sancus_wrap(body, body_len, NULL, 0, NULL, tag);
}

/**
 * Get the Sancus ID of the module loaded at @p addr.
 */
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

/**
 * Get the Sancus ID of the currently executing module.
 */
always_inline sm_id sancus_get_self_id(void)
{
    void* addr;
    asm("mov r0, %0" : "=m"(addr));
    return sancus_get_id(addr);
}

/**
 * Get the ID of the calling module.
 *
 * The calling module is defined as the previously executing module. That is,
 * the module that entered the currently executing module.
 */
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

/**
 * Annotation for module entry points.
 *
 * Use as follows:
 * @code
 * void SM_ENTRY("mod_name") entry_name(void) {...}
 * @endcode
 */
#define SM_ENTRY(name) __ANNOTATE("sm_entry:" name) __attribute__((noinline, used))

/**
 * Annotation for internal module function (i.e., not entry points).
 *
 * @see SM_ENTRY()
 */
#define SM_FUNC(name)  __ANNOTATE("sm:" name)

/**
 * Annotation for data the should be part of the secret section.
 *
 * Note that the secret section is always zero-initialized. This means that data
 * cannot be initialized if it is to be placed in the secret section.
 *
 * Use as follows:
 * @code
 * int SM_DATA("mod_name") data_name;
 * @endcode
 */
#define SM_DATA(name)  SM_FUNC(name)

/**
 * Interrupt vector for the Sancus violation ISR.
 *
 * Use as follows:
 * @code
 * void __attribute__((interrupt(SM_VECTOR))) the_isr(void) {...}
 * @endcode
 */
#define SM_VECTOR 26

/**
 * Return value of sancus_get_caller_id() for unprotected code.
 */
#define SM_ID_UNPROTECTED 0

/**
 * Return value of sancus_get_caller_id() for an IRQ.
 */
#define SM_ID_IRQ 0xffff

#endif

