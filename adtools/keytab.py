# Reference for keytab file format:
#   - https://www.gnu.org/software/shishi/manual/html_node/The-Keytab-Binary-File-Format.html

import struct
import StringIO
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Hash import MD4
from Crypto.Protocol.KDF import PBKDF2
from adtools.nfold import krb5int_nfold

KRB_CONSTANT = "kerberos"
KRB_ENCTYPES = {
	"aes128-cts": {
		"bits": 128,
		"key_length": 16,
		"key_type": 17
		},
	"aes256-cts": {
		"bits": 256,
		"key_length": 32,
		"key_type": 18
		},
	"arcfour-hmac": {
		"key_length": 16,
		"key_type": 23
		}
	}

PBKDF2_ITERATIONS = 4096


class Keytab:

	def __init__(self, keytab_file=None):
		self.keytab_file = keytab_file

	def add_entry(self, enc, spn=None):
		enc_vals = KRB_ENCTYPES[enc]

		if spn:
			princ = spn
			components = princ.split("/")
		else:
			princ = self.principal
			components = [ princ ]

		# Write entry length
		ent_len = 21 + len(self.realm) + enc_vals['key_length']

		# The +2 is to accomodate the short indicating the component length
		for comp in components:
			ent_len += len(comp) + 2

		self.write_int(ent_len)

		# Write num_components
		self.write_short(len(components))

		# Write REALM length
		self.write_short(len(self.realm))

		# Write REALM name
		self.write(self.realm)

		for comp in components:
			# Write component length
			self.write_short(len(comp))

			# Write component name
			self.write(comp)

		# Write name_type (1)
		# 1 = KRB5_NT_PRINCIPAL
		# 2 = KRB5_NT_SRV_INST
		# 5 = KRB5_NT_UID
		# ...
		self.write_int(1)

		# Write timestamp in seconds since epoch
		self.write_int(int(datetime.now().strftime("%s")))

		# Write KVNO
		self.write_byte(self.kvno)

		# Write key type (23)
		# 3 = DES-CBC-MD5
		# 16 = DES3-CBC-SHA1
		# 17 = AES128-CTS
		# 18 = AES256-CTS
		# 23 = ARCFOUR-HMAC-MD5
		# ...
		self.write_short(enc_vals["key_type"])

		# Write key length
		# 16 = ARCFOUR-HMAC-MD5
		# 16 = AES128-CTS
		# 32 = AES256-CTS
		self.write_short(enc_vals["key_length"])

		# Write out key of password
		self.write_key(enc, enc_vals)

		# Write out KVNO again but 32-bit this time
		self.write_int(self.kvno)

	def save_to_disk(self):
		with open(self.keytab_file, "w") as f:
			f.write(self.keytab_contents)

	def create(self, name, realm, password, enctypes, spns=None, kvno=2, spns_only=False, account_type_computer=True):
		self.name = name
		self.realm = realm
		self.password = password
		self.keytab = StringIO.StringIO()
		self.enctypes = enctypes
		self.spns = spns
		self.spns_only = spns_only

		# How to salt for AD
		# [MS-KILE] 3.1.1.2 - Cryptographic Material
		# https://msdn.microsoft.com/en-us/library/cc233883.aspx
		if account_type_computer:
			self.principal = "%s$" % self.name.upper()
			self.salt = "%shost%s.%s" % (self.realm.upper(), self.name.lower(), self.realm.lower())
		else:
			self.principal = self.name
			self.salt = "%s%s" % (self.realm.upper(), self.name)

		self.kvno = kvno

		self.write_header()
		self.process_enctypes()

		# Save contents to var and close keytab
		self.keytab_contents = self.keytab.getvalue()
		self.keytab.close()

		if self.keytab_file:
			self.save_to_disk()

	def process_enctypes(self):
		for enc in self.enctypes:
			if enc not in KRB_ENCTYPES.keys():
				raise Exception("Not a valid enctype: %s" % enc)

			if not self.spns_only:
				self.add_entry(enc)

			if self.spns:
				for spn in self.spns:
					self.add_entry(enc, spn)

	def write(self, data):
		self.keytab.write(data)

	def write_byte(self, byte):
		self.write(struct.pack("b", byte))

	def write_header(self):
		self.write("\x05\x02")

	def write_int(self, num):
		self.write(struct.pack(">i", num))

	def write_key(self, enc, enc_vals):
		if enc == "arcfour-hmac":
			# Write out RC4 key of password
			self.write(MD4.new(self.password.encode('utf_16_le')).digest())
		elif enc.startswith("aes"):
			# Write out AES key of password
			tkey = PBKDF2(self.password, self.salt, enc_vals["bits"], PBKDF2_ITERATIONS)[:enc_vals["key_length"]]
			cipher = AES.new(tkey)
			key1 = cipher.encrypt(krb5int_nfold(KRB_CONSTANT, 16))
			if enc_vals["bits"] == 256:
			    key2 = cipher.encrypt(key1)
			    key = key1 + key2
			else:
			    key = key1
			self.write(key)

	def write_short(self, short):
		self.write(struct.pack(">h", short))

