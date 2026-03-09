# UAF
- UAF，即**use after free** ,指的是对象已经被 free / delete并且数据没有被置0
但程序仍然使用该指针
- 形成条件    
条件       说明  
内存分配    malloc/new申请堆内存  
内存释放	free/delete 释放，但指针未置空  
内存重用	分配器将同一块内存分配给其他对象  
原指针使用	操作已变更内容的内存	

- 主要利用方式   
```
目标 —— 方法——   效果   
函数指针 —— 覆盖为 system/one_gadget——	代码执行   
vtable 指针——伪造虚表，劫持虚函数调用——代码执行  
堆指针（fd/next）——tcache/fastbin poisoning——任意地址写   
chunk size——篡改大小，扩展读写范围——堆溢出	
```
- 例题    
[/mnt/d/download/pwn/pwn_notes/题目/堆/uaf/BUUCTF_uaf_纯/hacknote]