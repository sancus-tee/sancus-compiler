#ifndef SPM_SUPPORT_H
#define SPM_SUPPORT_H

typedef unsigned spm_id;

struct Spm
{
    spm_id id;
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

#define DECLARE_SPM(name)                                       \
    extern char __PS(name), __PE(name), __SS(name), __SE(name); \
    struct Spm name = {0, #name, &__PS(name), &__PE(name),      \
                       &__SS(name), &__SE(name)}

int protect_spm(struct Spm* spm);

inline void __attribute__((always_inline)) unprotect_spm()
{
    asm(".word 0x1380");
}

#define __ANNOTATE(x) __attribute__((annotate(x)))

#define SPM_FUNC(name)  __ANNOTATE("spm:" name)
#define SPM_ENTRY(name) __ANNOTATE("spm_entry:" name)

#endif
