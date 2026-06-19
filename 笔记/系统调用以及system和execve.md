## 常用syscall系统调用号以及各个系统调用函数的参数
```py
   #open (打开文件)
rax: 2
rdi: 指向文件路径字符串的指针 (例如 /flag)。
rsi: 标志位 (flag)。通常填 0 (只读 O_RDONLY)。
rdx: 权限 (mode)。如果只是打开文件读取，可以填 0。
   #read (读文件)
rax: 0
rdi: 文件描述符 (fd)。0=stdin, 1=stdout, 2=stderr。如果是 open 返回的 fd，通常是某个大于 2 的值。
rsi: 缓冲区地址 (buf)。你想把读到的数据放在内存的哪个位置 (例如 .bss 段)。
rdx: 要读取的字节数 (count)。例如 0x100。
   #write (写文件/输出)
rax: 1
rdi: 文件描述符 (fd)。通常是 1 (stdout) 或 2 (stderr)。
rsi: 缓冲区地址 (buf)。你想输出的内存数据地址。
rdx: 要写入的字节数 (count)。
   #execve (执行程序)
rax: 59
rdi: 程序路径 (filename)。指向 /bin/sh 或 /bin/cat 的指针。
rsi: 参数数组 (argv)。指向一个数组的指针，数组里存着指针（例如 [&"/bin/sh", 0]）。
rdx: 环境变量 (envp)。通常填 0。

#设置好参数后直接调用syscall(gadget),32位中等效为int 0x80
```

## 关于execve的具体细节以及其与system的关系
```py
    #参数细节
参数 1 (rdi): 指向程序路径的指针。例如 /bin/sh 的内存地址。
参数 2 (rsi): 指向参数数组的指针。这是一个 char **。它指向一个数组，数组的第一个元素是程序名（如 /bin/sh），第二个元素是参数（如 -c），最后一个必须是 NULL。
参数 3 (rdx): 指向环境变量数组的指针。通常设为 NULL (0) 即可
   #参数细节实现
execve("/bin/sh", NULL, NULL)
execve("/bin/sh", ["/bin/sh"], NULL)
execve("/bin/cat", ["/bin/cat", "/flag"], NULL)#cat flag
#第2,3的第二个参数均为指针数组的地址，注意第3个不可以填成"flag"的地址，有题见【/mnt/d/download/pwn/pwn_notes/题目/栈/ret2csu/ret2csu1(syscall)/1.py’】
当文件路径为/bin/sh，这个sh其实是个shell程序，如果argv是空（0也可以），那么就会去打开一个shell，所以execve("/bin/sh",0,0)是我们最常用的，but如果argv不为空呢，sh就可以变成变成一个shell脚本解析器，这时候argv应该是这么组成char *argv[]={"/bin/sh","flag",NULL}这样子这个数组的第一个内容是文件路径
```
```py
   #与system关系
system 的执行流程是 fork + execve + waitpid。
fork: 首先创建一个子进程。
execve: 在子进程中，通过 execve 系统调用去加载并执行你指定的命令（例如 /bin/sh -c "your_command"）。
waitpid: 父进程等待子进程执行完毕后，再继续自己的流程。

execve 是真正执行程序的系统调用，而 system 是一个封装好的库函数，它利用 execve 在一个独立的进程中执行命令，并等待其结束。
```




```


## ORW套路
```py
open: rdi=地址("/flag"), rsi=0 -> 执行后通常会把文件描述符（比如 3）放在 rax 里。
read: rdi=3 (上一步得到的 fd), rsi=地址(.bss), rdx=0x100 -> 把内容读到 .bss 段。
write: rdi=1 (stdout), rsi=地址(.bss), rdx=0x100 -> 把 .bss 段内容打印到屏幕上。
#若本地调试时程序中无‘flag’，需要先把'/flag'通过read写入，因此变为rorw
```