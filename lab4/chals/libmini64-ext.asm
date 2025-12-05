%include "libmini.inc"

section .bss
    seed resq 1        ; 8 bytes for unsigned long long seed

section .text

global time
time:
    ; syscall number for time = 201
    mov     rax, 201        ; syscall: time
    xor     rdi, rdi        ; argument: NULL (ignore time_t * argument)
    syscall                 
    ret                    ; return value is already in rax


global srand
srand:
    ; void srand(unsigned int s)
    ; input: rdi = s
    mov     rax, rdi
    dec     rax         
    mov     [rel seed], rax
    ret


global grand
grand:
    ; unsigned int grand(void)
    mov     rax, [rel seed]
    ret


global rand
rand:
    ; int rand(void)
    mov     rax, [rel seed]
    mov     rbx, 6364136223846793005
    mul     rbx

    inc     rax

    mov     [rel seed], rax
    shr     rax, 33
    ret


global sigfillset
sigfillset:
    ; int sigfillset(sigset_t *set)
    ; input: rdi = pointer to sigset_t
    ; output: 0 on success, -1 on error
    mov     rax, 0
    mov     rbx, 0xFFFFFFFFFFFFFFFF
    mov     [rdi], rbx
    ret

global sigemptyset
sigemptyset:
    ; int sigemptyset(sigset_t *set)
    ; input: rdi = pointer to sigset_t
    ; output: 0 on success, -1 on error
    mov     rax, 0
    xor     rbx, rbx
    mov     [rdi], rbx
    ret

global sigaddset
sigaddset:
    ; int sigaddset(sigset_t *set, int signum)
    ; input: rdi = pointer to sigset_t, rsi = signum
    ; output: 0 on success, -1 on error
    mov     rax, 0
    mov     rbx, [rdi]
    mov     cl, sil 
    dec     cl      ; set the bit position to 0-based

    xor     rdx, rdx
    inc     rdx
    shl     rdx, cl
    or      rbx, rdx
    mov     [rdi], rbx
    ret

global sigdelset
sigdelset:
    ; int sigdelset(sigset_t *set, int signum)
    ; input: rdi = pointer to sigset_t, rsi = signum
    ; output: 0 on success, -1 on error
    mov     rax, 0
    mov     rbx, [rdi]
    mov     cl, sil 
    dec     cl      ; set the bit position to 0-based

    xor     rdx, rdx
    inc     rdx
    shl     rdx, cl
    not     rdx
    and     rbx, rdx
    mov     [rdi], rbx
    ret

global sigismember
sigismember:
    ; int sigismember(const sigset_t *set, int signum)
    ; input: rdi = pointer to sigset_t, rsi = signum
    ; output: 1 if member, 0 if not
    mov     rbx, [rdi]
    mov     cl, sil 
    dec     cl      ; set the bit position to 0-based

    xor     rdx, rdx
    inc     rdx
    shl     rdx, cl
    and     rbx, rdx
    cmp     rbx, 0
    jne     .is_member
    mov     rax, 0
    ret
.is_member:
    mov     rax, 1
    ret

global sigprocmask
sigprocmask:
    ; int sigprocmask(int how, const sigset_t *newset, sigset_t *oldset)
    ;
    ; rdi = how
    ; rsi = newset
    ; rdx = oldset
    ;
    ; syscall(SYS_rt_sigprocmask, how, newset, oldset, sizeof(sigset_t))

    mov     r10, 8              ; sigset_t size = 8 bytes
    mov     rax, 14             ; syscall number for rt_sigprocmask
    syscall                     ; perform syscall
    ret

global setjmp
setjmp:
    ; int setjmp(jmp_buf env)
    ; input: rdi = pointer to jmp_buf
    ; output: 0 if returning from setjmp, non-zero if returning from longjmp
    mov     [rdi], rbx
    mov     [rdi+8], rbp
    mov     [rdi+16], rsp
    mov     [rdi+24], r12
    mov     [rdi+32], r13
    mov     [rdi+40], r14
    mov     [rdi+48], r15
    mov     rax, [rsp]
    mov     [rdi+56], rax
    
    mov     rsi, 0          ; newset = NULL
    lea     rdx, [rdi+64]   ; &env->mask
    mov     rdi, 2          ; how = SIG_SETMASK
    mov     r10, 8
    mov     rax, 14
    syscall

    ; setjmp return value = 0
    xor     eax, eax
    ret

global longjmp
longjmp:
    ; void longjmp(jmp_buf env, int ret)
    ; input: rdi = pointer to jmp_buf, rsi = ret
    ; output: jumps to the location saved in jmp_buf
    mov     rbx, [rdi]
    mov     rbp, [rdi+8]
    mov     rsp, [rdi+16]
    mov     r12, [rdi+24]
    mov     r13, [rdi+32]
    mov     r14, [rdi+40]
    mov     r15, [rdi+48]
    mov     r8 , [rdi+56]   ; return address
    mov     r9 , rsi        ; ret value

    ; restore signal mask
    lea     rsi, [rdi+64]   ; &env->mask
    mov     rdi, 2          ; how = SIG_SETMASK
    mov     rdx, 0          ; oldset = NULL
    mov     r10, 8
    mov     rax, 14
    syscall

    mov     rax, r9
    test    rax, rax
    jne     .skip_zero
    mov     rax, 1
.skip_zero:
    add     rsp, 8
    push    r8
    ret