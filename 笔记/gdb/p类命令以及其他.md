## p类
```py
pwndbg>p fun_name # 打印函数地址
pwndbg>p 0x10-0x08 # 计算0x10-0x08的结果
pwndbg>p *(0x123456789) # 查看指定地址指向的值
pwndbg>p $rdi # 查看寄存器存放的地址
pwndbg>p *($rdi) # 查看rdi存放的地址指向的值
```

## info类（简称i）
```py
pwndbg>info b # 查看所有断点
pwndbg>info functions # 查看所有函数
pwndbg>info sharedlibrary # 查看共享链接库
pwndbg>info sharedlibrary hiredi* # 查看指定共享链接库，可以用前缀 + * 匹配
```

## telescope类（简称tel）
```py
telescope $rsp #从栈顶指针开始，查看栈上的内容。通常能看到返回地址。
telescope $rsp 10 #从栈顶开始，查看 10 个地址长度的内存（64位下约 10 行，80字节）。
telescope $rsp 10 2 #从栈顶开始，查看 10 个单元，深度为 2。即不仅看栈上的指针，还顺着指针再看一层指向的内容。
telescope &global_var #查看全局变量 global_var 的地址及其内容。
telescope $rdi #查看函数参数（如 puts 函数的参数），常用于确认泄露的地址内容。
telescope 0x555555558000 #从指定的堆或 bss 段地址开始查看内存布局。
```

## search类
```py
search /bin/sh #在整个内存空间搜索字符串 /bin/sh (如果程序加载了 libc，通常能找到)。
search 0x7ffff7a56ab0 #搜索一个具体的地址（例如你泄露出来的 puts 地址），确认它位于哪片内存区域。
search -t string "flag{" #搜索特定的字符串模式（如 flag 的开头）。
search -t byte 00 #搜索特定的字节值（例如寻找溢出时的 null 字节限制）。
search main #搜索函数 main 的地址。
#    -t代表--type
```

## 堆类
```py
heap
#以数据结构的形式显示所有堆块（chunk）的信息，会列出每个堆块的地址、大小和状态。
heap chunks
#列出当前堆上所有已分配和未分配的堆块，信息非常详细。
heap base
#查看程序堆（heap）的起始地址。
bins
#一次性查看所有种类的 bin（包括 tcache, fastbin, unsortedbin, smallbin, largebin）的链表情况。
tcache
#单独查看 tcache（Thread Cache）的详细信息。
fastbins
#单独查看 fastbins 的链表情况。
unsortedbin
#单独查看 unsortedbin 的链表情况。
smallbins
#单独查看 smallbins 的链表情况。
largebins
#单独查看 largebins 的链表情况。
arena
#显示当前线程分配区（arena）的详细信息。
vis
#以图形化的方式展示堆内存的分布情况，非常直观。
parseheap
#解析并显示堆的整体结构，也是一个很好用的命令。
tracemalloc
#追踪程序中对 malloc 和 free 的所有操作，有助于分析堆的分配和释放过程。







```