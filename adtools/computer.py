import kerberos
import ldap
from adtools.keytab import Keytab

COMPUTERS_RDN = "CN=Computers"

class Computer:

	def __init__(self):
		pass

	def build_keytab(self, keytab, enctypes):
		tab = Keytab(keytab)
		tab.create(self.name, self.realm, self.password, enctypes, self.spns)

	def build_ldif(self):
		self.ldif = [
			("objectClass", [ 
				"top",
				"person",
				"organizationalPerson",
				"user",
				"computer"
				]),
			("cn", self.name_upper),
			("distinguishedName", self.new_computer_dn),
			("instanceType", "4"),
			("name", self.name_upper),
			("userAccountControl", "4096"),
			("codePage", "0"),
			("countryCode", "0"),
			("accountExpires", "0"),
			("objectCategory", "CN=Computer,CN=Schema,CN=Configuration,%s" % self.base_dn),
			("displayName", "%s$" % self.name_upper),
			("sAMAccountName", "%s$" % self.name_upper)
			]
		if self.spns:
			self.ldif.append(("servicePrincipalName", self.spns))

	def change_password(self):
		passChanged = kerberos.changePassword(self.principal, "", self.password)

		if not passChanged:
			raise Exception("Could not set computer password")

	def create(self, name, dc, realm, password=None, base_dn=None, computers_dn=None, keytab=None, keytab_enctypes=None, spns=None):
		# Computer object's name
		self.name = name.lower()
		self.name_upper = name.upper()
		self.principal = "%s$" % self.name_upper
		# Computer password
		if not password:
			self.password = self.name
		else:
			self.password = password
		# Domain Controller
		self.dc = dc
		# AD/Kerberos REALM
		self.realm = realm
		# Base DN for AD/LDAP
		if not base_dn:
			self.base_dn = "DC=" + ",DC=".join(realm.split('.'))
		else:
			self.base_dn = base_dn
		# Where to place new Computer object
		if not computers_dn:
			self.computers_dn = "%s,%s" % (COMPUTERS_RDN, self.base_dn)
		else:
			self.computers_dn = computers_dn
		self.new_computer_dn = "CN=%s,%s" % (self.name_upper, self.computers_dn)
		# Additional SPNs for Computer object
		self.spns = spns
		
		self.build_ldif()
		self.create_computer_object()
		self.change_password()

		if keytab:
			if not keytab_enctypes:
				keytab_enctypes = [ "aes256-cts" ]
			self.build_keytab(keytab, keytab_enctypes)

	def create_computer_object(self):
		conn = ldap.initialize("ldap://%s" % self.dc)
		conn.sasl_non_interactive_bind_s("GSSAPI")

		ret = conn.add_s(self.new_computer_dn, self.ldif)

