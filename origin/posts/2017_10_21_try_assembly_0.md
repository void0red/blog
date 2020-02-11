---
title: "try_assembly_0"
date: 2017-10-21
tags: asm
---

> if-else, while/for, switch-case
>
> 编译器：`gcc (Ubuntu 5.4.0-6ubuntu1~16.04.4) 5.4.0 20160609`
<!-- more -->

## if-else
一段c的代码
```c
#include <stdio.h>
int main(){
	int x = 1;
	int y = 2;
	if(x == y){
		printf("equal");
	}else{
		printf("233");
	}
	return 0;
}
```
用`gcc -c if-else.c`得到目标文件

用`objdump -S if-else.o`查看代码段的汇编

```
   0:	55                   	push   %rbp
   1:	48 89 e5             	mov    %rsp,%rbp
   4:	48 83 ec 10          	sub    $0x10,%rsp
   8:	c7 45 f8 01 00 00 00 	movl   $0x1,-0x8(%rbp)
   f:	c7 45 fc 02 00 00 00 	movl   $0x2,-0x4(%rbp)
  16:	8b 45 f8             	mov    -0x8(%rbp),%eax
  19:	3b 45 fc             	cmp    -0x4(%rbp),%eax
  1c:	75 11                	jne    2f <main+0x2f>
  1e:	bf 00 00 00 00       	mov    $0x0,%edi
  23:	b8 00 00 00 00       	mov    $0x0,%eax
  28:	e8 00 00 00 00       	callq  2d <main+0x2d>
  2d:	eb 0f                	jmp    3e <main+0x3e>
  2f:	bf 00 00 00 00       	mov    $0x0,%edi
  34:	b8 00 00 00 00       	mov    $0x0,%eax
  39:	e8 00 00 00 00       	callq  3e <main+0x3e>
  3e:	b8 00 00 00 00       	mov    $0x0,%eax
  43:	c9                   	leaveq 
  44:	c3                   	retq   
```

理解：

- 0-f：喜闻乐见的函数开头，压入rbp寄存器的值（保存堆栈帧的基址），把栈指针rsp保存到rbp，栈顶指针下移16字节，（为局部变量保留空间），把x=1,y=2,压入栈中
- 16-1c：把x=1放入eax寄存器中，与y=2比较大小，如果不相等，跳转到2f处执行
- 1e-28：调用printf的一套操作，清空edi，eax，然后调用
- 2d：无条件跳转到3e段
- 2f-39：同1e-28
- 3e-44：喜闻乐见的函数结尾，把eax清零（返回值为0），恢复堆栈帧（恢复esp的值，弹出ebp的值），函数返回

## while/for
一段c代码

```c
#include <stdio.h>
int main(){
	for(int x = 0; x < 10; x++){
		printf("%d\n",x);
	}

	int x = 0;

	while(x < 10){
		printf("%d\n",x);
		x++;
	}
	return 0;
}
```

代码段的汇编

```
   0:	55                   	push   %rbp
   1:	48 89 e5             	mov    %rsp,%rbp
   4:	48 83 ec 10          	sub    $0x10,%rsp
   8:	c7 45 f8 00 00 00 00 	movl   $0x0,-0x8(%rbp)
   f:	eb 18                	jmp    29 <main+0x29>
  11:	8b 45 f8             	mov    -0x8(%rbp),%eax
  14:	89 c6                	mov    %eax,%esi
  16:	bf 00 00 00 00       	mov    $0x0,%edi
  1b:	b8 00 00 00 00       	mov    $0x0,%eax
  20:	e8 00 00 00 00       	callq  25 <main+0x25>
  25:	83 45 f8 01          	addl   $0x1,-0x8(%rbp)
  29:	83 7d f8 09          	cmpl   $0x9,-0x8(%rbp)
  2d:	7e e2                	jle    11 <main+0x11>
  2f:	c7 45 fc 00 00 00 00 	movl   $0x0,-0x4(%rbp)
  36:	eb 18                	jmp    50 <main+0x50>
  38:	8b 45 fc             	mov    -0x4(%rbp),%eax
  3b:	89 c6                	mov    %eax,%esi
  3d:	bf 00 00 00 00       	mov    $0x0,%edi
  42:	b8 00 00 00 00       	mov    $0x0,%eax
  47:	e8 00 00 00 00       	callq  4c <main+0x4c>
  4c:	83 45 fc 01          	addl   $0x1,-0x4(%rbp)
  50:	83 7d fc 09          	cmpl   $0x9,-0x4(%rbp)
  54:	7e e2                	jle    38 <main+0x38>
  56:	b8 00 00 00 00       	mov    $0x0,%eax
  5b:	c9                   	leaveq 
  5c:	c3                   	retq   
```

理解：
- 0-4：函数头部
- 8：局部变量x=0入栈
- f：跳转29处
- 11-20：打印x的值
- 25：增加x的值
- 29-2d：比较9与x的值，小于或等于时跳转11处
- 2f：局部变量x=0入栈
- 36：跳转50处
- 38-47：打印x的值
- 4c：增加x的值
- 50-54：比较9与x的值，小于或等于时跳转38处
- 56-5c：函数尾部

（for和while的实现方式貌似差不多）

## switch-case
一段c代码
```c
#include <stdio.h>
int main(){
	int x = 1;
	switch( x ){
		case 0:printf("case 0\n");break;
		case 1:printf("case 1\n");break;
		case 2:printf("case 2\n");break;
		default:printf("default\n");break;
	}
	return 0;
}
```

代码段的汇编
```
   0:	55                   	push   %rbp
   1:	48 89 e5             	mov    %rsp,%rbp
   4:	48 83 ec 10          	sub    $0x10,%rsp
   8:	c7 45 fc 01 00 00 00 	movl   $0x1,-0x4(%rbp)
   f:	8b 45 fc             	mov    -0x4(%rbp),%eax
  12:	83 f8 01             	cmp    $0x1,%eax
  15:	74 15                	je     2c <main+0x2c>
  17:	83 f8 02             	cmp    $0x2,%eax
  1a:	74 1c                	je     38 <main+0x38>
  1c:	85 c0                	test   %eax,%eax
  1e:	75 24                	jne    44 <main+0x44>
  20:	bf 00 00 00 00       	mov    $0x0,%edi
  25:	e8 00 00 00 00       	callq  2a <main+0x2a>
  2a:	eb 23                	jmp    4f <main+0x4f>
  2c:	bf 00 00 00 00       	mov    $0x0,%edi
  31:	e8 00 00 00 00       	callq  36 <main+0x36>
  36:	eb 17                	jmp    4f <main+0x4f>
  38:	bf 00 00 00 00       	mov    $0x0,%edi
  3d:	e8 00 00 00 00       	callq  42 <main+0x42>
  42:	eb 0b                	jmp    4f <main+0x4f>
  44:	bf 00 00 00 00       	mov    $0x0,%edi
  49:	e8 00 00 00 00       	callq  4e <main+0x4e>
  4e:	90                   	nop
  4f:	b8 00 00 00 00       	mov    $0x0,%eax
  54:	c9                   	leaveq 
  55:	c3                   	retq   
```

理解：
- 0-4：函数头部
- 8：x = 1入栈
- f-1a：与1相比较，如果相等的话，跳转2c处，与2相比较，如果相等的话，跳转38处
- 1c-1e：尝试x与x的and运算，只改变标志位C，O，如果结果不为0，跳转44处
- 20-2a：调用printf函数，跳转4f处（case 0）
- 2c-36：调用printf函数，跳转4f处（case 1）
- 38-42：调用printf函数，跳转4f处（case 2）
- 44-49：调用printf函数（default）
- 4e：空指令
- 4f-55：函数尾部

