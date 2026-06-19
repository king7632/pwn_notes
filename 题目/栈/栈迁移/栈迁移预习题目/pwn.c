#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h> // 引入 system 函数所需的头文件

// 1. 你要求加入的新函数
void secret_function() {
    system("echo 你咋直接来到这里了？");
}

// 嵌入 Gadgets 的特殊函数
__attribute__((used))
void gadgets() {
    __asm__(
        "pop %rdi; ret;"
    );
}

int task2()
{
    char buf[256]; // 缓冲区大小为 0x100

    puts("Let's try a more difficult task.");
    puts("Oh right, what's your name?");

    // 第一次读取：0x110 超过了 0x100，存在溢出风险
    // 用于 Leak 地址或触发下方的逻辑
    if ((int)read(0, buf, 0x110u) > 256)
    {
        // 这里的 printf(%s) 如果 buf 填满了，可以泄露栈上的残留地址（如 Canary 或 RBP/RET）
        printf("%s,your name is too long\n", buf);
        puts("rename it");
        
        // 第二次读取：用于放置 ROP 链，覆盖返回地址
        read(0, buf, 0x110u);
    }

    return puts("where /bin/sh");
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    task2();
    return 0;
}