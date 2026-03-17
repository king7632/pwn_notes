## 关于leak的接收方式有以下几种
```py
u64(p.recv(8))
u64(p.recv(6).ljust(8,b'\x00))
u64(p.recvline().strip().ljust(8,b'\x00'))
u64(p.recvuntil(b'\x7f)[-6:].ljust(8,b'\x00'))
```
- 其中**第2和第3**最安全，第4由于有时真实地址最高有效字节不是'\x7f'而不够稳妥，而第1则只适用于利用write(8)来泄漏时，因为**puts遇到'\x00'会截止**

## 关于patchelf使用
- 由于本地调试时二进制文件默认的ld加载器与libc是本地的，与比赛提供的**不同**（可以通过**ldd命令**查看），因此需要使用patchelf来更改libc与ld
- 更换ld:  patchelf --set-interpreter   /path/to/libc/ld-linux-x86-64.so.2   ./pwn
- 更换libc:  patchelf --replace-needed  libc.so.6(**系统默认**)  /path/to/libc/libc.so.6   ./pwn