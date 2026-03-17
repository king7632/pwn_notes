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