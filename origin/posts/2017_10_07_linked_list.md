---
title: "About learning linked_list"
date: 2017-10-24
tags: c
---
> some Pointer and Struct practicing

链表由两部分组成，一部分是指针区，一部分是数据区，这里要说的是单链表，指针区仅仅只是下一个节点的地址，为了简化程序，数据区也只设置一个整型变量
<!-- more -->
```c
//定义结构体,并且规定新类型node
typedef struct node{
	int data;//数据区
	struct node *next;//连接节点的量
}node;
//初始化头节点
node * node_init(){
	node * head = (node *)malloc(sizeof(node));//为头节点分配内存空间
	head -> next = NULL;//后一个节点置空
	head -> data = -1;//头节点的数据
	return head;//返回头节点的地址
}
//在链表末尾添加节点，返回节点指针
node * node_add(node *head, int data){
	node * newnode = (node *)malloc(sizeof(node));//为新节点分配空间
	if(!newnode)return NULL;//如果分配失败就返回空指针
	node *p = head;//定义指向头节点的临时指针
	while(p -> next != NULL )p = p -> next;//临时指针移动到末尾
	p -> next = newnode;//把新节点接到末尾
	newnode -> next = NULL;//新节点的后节点置空
	newnode -> data = data;//新节点储存数据
	return newnode;//返回新节点地址
}
//打印链表所有节点
void list_print(node *head){
	node *p = head;//定义指向头节点的临时指针
	int x = 0;
	while(p != NULL){
		printf("node(%d):%d\n", x, p -> data);
		p = p -> next;//不断指向下一节点
		x++;
	}
}
//在指定节点末尾插入新的节点（头节点为0号），返回节点指针
node * node_insert(node *head, int i,int data){
	node * newnode = (node *)malloc(sizeof(node));//为新节点分配空间
	if(!newnode)return NULL;//如果分配失败就返回空指针
	newnode -> data = data;//新节点储存数据
	node * p = head;//定义指向头节点的临时指针
	while(i > 0 && p -> next != NULL){
		p = p -> next;
		i--;
	}//不断指向下一节点,到指定位置
	newnode -> next = p -> next;//把指定位置的下一个节点连接到新节点上
	p -> next = newnode;//把指定位置的节点连接到新节点上
	return newnode;//返回新节点的地址
}
//删除指定节点（头节点为0号）
void node_del(node *head, int i){
	node *p1 = head;
	node *p2;
	if(i == 0)i++;//不允许删除头节点
	while(i > 0 && p1 -> next != NULL){
		i--;
		p2 = p1;
		p1 = p1 -> next;
	}//p1指向需要删除的节点,p2指向前一节点
	p2 -> next = p1 -> next;//把需要删除的节点空出来
	free(p1);//释放内存
}
//返回链表的节点数
int list_length(node *head){
	node *p = head;
	int count = 0;
	while(p != NULL){
		p = p -> next;
		count++;
	}//迭代计数
	return count;
}
//删除链表
void list_del(node *head){
	node * p1 = head;
	node * p2;
	while(p1 != NULL){
		p2 = p1;
		p1 = p1 -> next;
		free(p2);
	}//不断释放指向节点的前一节点内存,最终释放所有内存
}
//修改指定节点的数据（头节点为0号），反回修改的节点的指针
node * node_modify(node *head, int i, int data){
	node *p = head;
	while(i > 0){
		if(p -> next == NULL)return NULL;//如果超出范围,返回空指针
		p = p -> next;
		i--;
	}//寻找需要修改节点的地址
	p -> data = data;//修改数据区
	return p;//返回修改过节点的地址
}
```
