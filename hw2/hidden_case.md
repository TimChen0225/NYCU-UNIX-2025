# UP25 HW2 Hidden case
[TOC]

## Setup

Download link: [hw2_demo_program.zip](https://up.zoolab.org/unixprog/hw02/hw2_demo_program.zip)

:::info
Tips:

You can `ln -s /path/to/your/sdb sdb` inside your `hw2_demo_program`.

e.g.:

```shell
$ curl -sSfLO https://up.zoolab.org/unixprog/hw02/hw2_demo_program.zip
$ unzip hw2_demo_program.zip
Archive:  hw2_demo_program.zip
   creating: hw2_demo_program/
  inflating: hw2_demo_program/anon
  inflating: hw2_demo_program/hello
  inflating: hw2_demo_program/hola
  inflating: hw2_demo_program/ld-linux-x86-64.so.2
  inflating: hw2_demo_program/libc.so.6
  inflating: hw2_demo_program/mortis
  inflating: hw2_demo_program/rana
  inflating: hw2_demo_program/soyorin
$ ln -s ../../zig-out/bin/sdb hw2_demo_program/sdb
$ ls -al hw2_demo_program
total 5.6M
-rwxr-xr-x 1 501 dialout 801K Jun  1 10:45 anon
-rwxr-xr-x 1 501 dialout 801K Jun  1 10:45 hello
-rwxr-xr-x 1 501 dialout  21K Jun  1 10:45 hola
-rwxr-xr-x 1 501 dialout 236K Jun  1 10:45 ld-linux-x86-64.so.2
-rwxr-xr-x 1 501 dialout 2.2M Jun  1 10:45 libc.so.6
-rwxr-xr-x 1 501 dialout  23K Jun  1 10:45 mortis
-rwxr-xr-x 1 501 dialout 801K Jun  1 10:45 rana
lrwxr-xr-x 1 501 dialout   21 Jun  1 10:51 sdb -> ../../zig-out/bin/sdb
-rwxr-xr-x 1 501 dialout 845K Jun  1 10:45 soyorin
```
:::

## Hidden Case 1 (15%)

- input: `./sdb ./mortis`
```
info reg
break 401210
break 401214
cont
si
cont
si
patch 0x4011d8 580f05
patch 0x4011d4 31ff6a3c
si
cont
```

- output

```
** program './mortis' loaded. entry point: 0x401070.
      401070: f3 0f 1e fa                      endbr64
      401074: 31 ed                            xor       ebp, ebp
      401076: 49 89 d1                         mov       r9, rdx
      401079: 5e                               pop       rsi
      40107a: 48 89 e2                         mov       rdx, rsp
(sdb) info reg
$rax 0x000000000000001c    $rbx 0x0000000000000000    $rcx 0x00007ffed845da18
$rdx 0x0000788e0e8ee040    $rsi 0x0000788e0e923888    $rdi 0x0000788e0e9232e0
$rbp 0x0000000000000000    $rsp 0x00007ffed845da00    $r8  0x0000000000000840
$r9  0x0000080000000000    $r10 0x0000788e0e8e8860    $r11 0x0000788e0e8ffd70
$r12 0x0000000000401070    $r13 0x00007ffed845da00    $r14 0x0000000000000000
$r15 0x0000000000000000    $rip 0x0000000000401070    $eflags 0x0000000000000202
(sdb) break 401210
** set a breakpoint at 0x401210.
(sdb) break 401214
** set a breakpoint at 0x401214.
(sdb) cont
** hit a breakpoint at 0x401210.
      401210: 83 7d dc 04                      cmp       dword ptr [rbp - 0x24], 4
      401214: 7e be                            jle       0x4011d4
      401216: bf 00 00 00 00                   mov       edi, 0
      40121b: e8 6a ff ff ff                   call      0x40118a
      401220: b8 00 00 00 00                   mov       eax, 0
(sdb) si
** hit a breakpoint at 0x401214.
      401214: 7e be                            jle       0x4011d4
      401216: bf 00 00 00 00                   mov       edi, 0
      40121b: e8 6a ff ff ff                   call      0x40118a
      401220: b8 00 00 00 00                   mov       eax, 0
      401225: 48 8b 55 f8                      mov       rdx, qword ptr [rbp - 8]
(sdb) cont
I like cucumbers
** hit a breakpoint at 0x401210.
      401210: 83 7d dc 04                      cmp       dword ptr [rbp - 0x24], 4
      401214: 7e be                            jle       0x4011d4
      401216: bf 00 00 00 00                   mov       edi, 0
      40121b: e8 6a ff ff ff                   call      0x40118a
      401220: b8 00 00 00 00                   mov       eax, 0
(sdb) si
** hit a breakpoint at 0x401214.
      401214: 7e be                            jle       0x4011d4
      401216: bf 00 00 00 00                   mov       edi, 0
      40121b: e8 6a ff ff ff                   call      0x40118a
      401220: b8 00 00 00 00                   mov       eax, 0
      401225: 48 8b 55 f8                      mov       rdx, qword ptr [rbp - 8]
(sdb) patch 0x4011d8 580f05
** patch memory at 0x4011d8.
(sdb) patch 0x4011d4 31ff6a3c
** patch memory at 0x4011d4.
(sdb) si
      4011d4: 31 ff                            xor       edi, edi
      4011d6: 6a 3c                            push      0x3c
      4011d8: 58                               pop       rax
      4011d9: 0f 05                            syscall
      4011db: 65 20 63 48                      and       byte ptr gs:[rbx + 0x48], ah
(sdb) cont
** the target program terminated.
```
    
:::info
Please ensure that some registers (e.g. `$r13`) other than `$rip`, `$rsp`, and `$eflags` contain non-zero values in the `info reg` output.
:::

## Hidden Case 2 (15%)

- input: `./sdb ./soyorin`
```
info reg
breakrva 8943
breakrva 8947
cont
syscall
syscall
syscall
cont
info break
delete 1
info break
cont
delete 0
info break
cont
```

- output

```
** program './soyorin' loaded. entry point: 0x7c2215c917a0.
      7c2215c917a0: f3 0f 1e fa                      endbr64
      7c2215c917a4: 31 ed                            xor       ebp, ebp
      7c2215c917a6: 49 89 d1                         mov       r9, rdx
      7c2215c917a9: 5e                               pop       rsi
      7c2215c917aa: 48 89 e2                         mov       rdx, rsp
(sdb) info reg
$rax 0x0000000000000000    $rbx 0x0000000000000000    $rcx 0x0000000000000000
$rdx 0x0000000000000000    $rsi 0x0000000000000000    $rdi 0x0000000000000000
$rbp 0x0000000000000000    $rsp 0x00007fff19697340    $r8  0x0000000000000000
$r9  0x0000000000000000    $r10 0x0000000000000000    $r11 0x0000000000000000
$r12 0x0000000000000000    $r13 0x0000000000000000    $r14 0x0000000000000000
$r15 0x0000000000000000    $rip 0x00007c2215c917a0    $eflags 0x0000000000000200
(sdb) breakrva 8943
** set a breakpoint at 0x7c2215c91943.
(sdb) breakrva 8947
** set a breakpoint at 0x7c2215c91947.
(sdb) cont
** hit a breakpoint at 0x7c2215c91943.
      7c2215c91943: 83 7d dc 04                      cmp       dword ptr [rbp - 0x24], 4
      7c2215c91947: 7e be                            jle       0x7c2215c91907
      7c2215c91949: bf 00 00 00 00                   mov       edi, 0
      7c2215c9194e: e8 6a ff ff ff                   call      0x7c2215c918bd
      7c2215c91953: b8 00 00 00 00                   mov       eax, 0
(sdb) syscall
** hit a breakpoint at 0x7c2215c91947.
      7c2215c91947: 7e be                            jle       0x7c2215c91907
      7c2215c91949: bf 00 00 00 00                   mov       edi, 0
      7c2215c9194e: e8 6a ff ff ff                   call      0x7c2215c918bd
      7c2215c91953: b8 00 00 00 00                   mov       eax, 0
      7c2215c91958: 48 8b 55 f8                      mov       rdx, qword ptr [rbp - 8]
(sdb) syscall
** enter a syscall(1) at 0x7c2215cd7f8b.
      7c2215cd7f8b: 0f 05                            syscall
      7c2215cd7f8d: 48 3d 01 f0 ff ff                cmp       rax, -0xfff
      7c2215cd7f93: 73 01                            jae       0x7c2215cd7f96
      7c2215cd7f95: c3                               ret
      7c2215cd7f96: 48 c7 c1 b8 ff ff ff             mov       rcx, 0xffffffffffffffb8
(sdb) syscall
She is my friend
** leave a syscall(1) = 17 at 0x7c2215cd7f8b.
      7c2215cd7f8b: 0f 05                            syscall
      7c2215cd7f8d: 48 3d 01 f0 ff ff                cmp       rax, -0xfff
      7c2215cd7f93: 73 01                            jae       0x7c2215cd7f96
      7c2215cd7f95: c3                               ret
      7c2215cd7f96: 48 c7 c1 b8 ff ff ff             mov       rcx, 0xffffffffffffffb8
(sdb) cont
** hit a breakpoint at 0x7c2215c91943.
      7c2215c91943: 83 7d dc 04                      cmp       dword ptr [rbp - 0x24], 4
      7c2215c91947: 7e be                            jle       0x7c2215c91907
      7c2215c91949: bf 00 00 00 00                   mov       edi, 0
      7c2215c9194e: e8 6a ff ff ff                   call      0x7c2215c918bd
      7c2215c91953: b8 00 00 00 00                   mov       eax, 0
(sdb) info break
Num     Address
0       0x7c2215c91943
1       0x7c2215c91947
(sdb) delete 1
** delete breakpoint 1.
(sdb) info break
Num     Address
0       0x7c2215c91943
(sdb) cont
She is my friend
** hit a breakpoint at 0x7c2215c91943.
      7c2215c91943: 83 7d dc 04                      cmp       dword ptr [rbp - 0x24], 4
      7c2215c91947: 7e be                            jle       0x7c2215c91907
      7c2215c91949: bf 00 00 00 00                   mov       edi, 0
      7c2215c9194e: e8 6a ff ff ff                   call      0x7c2215c918bd
      7c2215c91953: b8 00 00 00 00                   mov       eax, 0
(sdb) delete 0
** delete breakpoint 0.
(sdb) info break
** no breakpoints.
(sdb) cont
She is my friend
She is my friend
She is my friend
** the target program terminated.
```
    
:::info
Please ensure that all registers, except for `$rip`, `$rsp`, and `$eflags`, are zero in the `info reg` output.

In addition, the addresses in the disassembly output may differ because the tracee is a PIE-enabled binary.
:::

## Hidden Case 3 (15%)

- input: `./sdb ./rana`
```
break 40179e
cont
break 4017a0
patch 40179e 7f1148
info break
cont
patch 40179e 7e
delete 0
cont
delete 1
cont
```

- output

```
** program './rana' loaded. entry point: 0x401650.
      401650: f3 0f 1e fa                      endbr64
      401654: 31 ed                            xor       ebp, ebp
      401656: 49 89 d1                         mov       r9, rdx
      401659: 5e                               pop       rsi
      40165a: 48 89 e2                         mov       rdx, rsp
(sdb) break 40179e
** set a breakpoint at 0x40179e.
(sdb) cont
** hit a breakpoint at 0x40179e.
      40179e: 7e 11                            jle       0x4017b1
      4017a0: 48 8d 05 5d 68 09 00             lea       rax, [rip + 0x9685d]
      4017a7: 48 89 c7                         mov       rdi, rax
      4017aa: e8 11 aa 00 00                   call      0x40c1c0
      4017af: eb 0f                            jmp       0x4017c0
(sdb) break 4017a0
** set a breakpoint at 0x4017a0.
(sdb) patch 40179e 7f1148
** patch memory at 0x40179e.
(sdb) info break
Num     Address
0       0x40179e
1       0x4017a0
(sdb) cont
live!
** hit a breakpoint at 0x40179e.
      40179e: 7f 11                            jg        0x4017b1
      4017a0: 48 8d 05 5d 68 09 00             lea       rax, [rip + 0x9685d]
      4017a7: 48 89 c7                         mov       rdi, rax
      4017aa: e8 11 aa 00 00                   call      0x40c1c0
      4017af: eb 0f                            jmp       0x4017c0
(sdb) patch 40179e 7e
** patch memory at 0x40179e.
(sdb) delete 0
** delete breakpoint 0.
(sdb) cont
** hit a breakpoint at 0x4017a0.
      4017a0: 48 8d 05 5d 68 09 00             lea       rax, [rip + 0x9685d]
      4017a7: 48 89 c7                         mov       rdi, rax
      4017aa: e8 11 aa 00 00                   call      0x40c1c0
      4017af: eb 0f                            jmp       0x4017c0
      4017b1: 48 8d 05 5b 68 09 00             lea       rax, [rip + 0x9685b]
(sdb) delete 1
** delete breakpoint 1.
(sdb) cont
matcha parfait
matcha parfait
** the target program terminated.
```

## Hidden Case 4 (15%)

- input: `./sdb ./anon`
```
breakrva 1828
cont
break 700000000000
cont
patch 0x700000000fc9 6844200b018134240101010148b875616e67204c4f565048b850726f662e206368504889e66a015f6a135a6a01580f0531ff6a3c58
syscall
syscall
si
patch 0x700000000ffe 0f05
break 700000000ffd
cont
delete 2
cont
```

- output

```
** program './anon' loaded. entry point: 0x401650.
      401650: f3 0f 1e fa                      endbr64
      401654: 31 ed                            xor       ebp, ebp
      401656: 49 89 d1                         mov       r9, rdx
      401659: 5e                               pop       rsi
      40165a: 48 89 e2                         mov       rdx, rsp
(sdb) breakrva 1828
** set a breakpoint at 0x401828.
(sdb) cont
** hit a breakpoint at 0x401828.
      401828: ff d2                            call      rdx
      40182a: 48 8d 05 cf 38 0c 00             lea       rax, [rip + 0xc38cf]
      401831: 48 89 c7                         mov       rdi, rax
      401834: e8 37 ae 00 00                   call      0x40c670
      401839: b8 00 00 00 00                   mov       eax, 0
(sdb) break 700000000000
** set a breakpoint at 0x700000000000.
(sdb) cont
** hit a breakpoint at 0x700000000000.
      700000000000: 90                               nop
      700000000001: 90                               nop
      700000000002: 90                               nop
      700000000003: 90                               nop
      700000000004: 90                               nop
(sdb) patch 0x700000000fc9 6844200b018134240101010148b875616e67204c4f565048b850726f662e206368504889e66a015f6a135a6a01580f0531ff6a3c58
** patch memory at 0x700000000fc9.
(sdb) syscall
** enter a syscall(1) at 0x700000000ff7.
      700000000ff7: 0f 05                            syscall
      700000000ff9: 31 ff                            xor       edi, edi
      700000000ffb: 6a 3c                            push      0x3c
      700000000ffd: 58                               pop       rax
      700000000ffe: 90                               nop
(sdb) syscall
{some interesting output}
** leave a syscall(1) = 19 at 0x700000000ff7.
      700000000ff7: 0f 05                            syscall
      700000000ff9: 31 ff                            xor       edi, edi
      700000000ffb: 6a 3c                            push      0x3c
      700000000ffd: 58                               pop       rax
      700000000ffe: 90                               nop
(sdb) si
      700000000ffb: 6a 3c                            push      0x3c
      700000000ffd: 58                               pop       rax
      700000000ffe: 90                               nop
      700000000fff: c3                               ret
** the address is out of the range of the executable region.
(sdb) patch 0x700000000ffe 0f05
** patch memory at 0x700000000ffe.
(sdb) break 700000000ffd
** set a breakpoint at 0x700000000ffd.
(sdb) cont
** hit a breakpoint at 0x700000000ffd.
      700000000ffd: 58                               pop       rax
      700000000ffe: 0f 05                            syscall
** the address is out of the range of the executable region.
(sdb) delete 2
** delete breakpoint 2.
(sdb) cont
** the target program terminated.
```
