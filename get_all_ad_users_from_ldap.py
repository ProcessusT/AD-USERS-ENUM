#!/usr/bin/env python3
import sys
import argparse
from impacket.ldap import ldap
from impacket.examples.utils import parse_target
import traceback
import binascii
import struct


def main():
	print("**************************************************\n\t           AD ENUM\n\n\t         @Processus\n\t            v1.0\n**************************************************\n\n")

	parser = argparse.ArgumentParser(add_help = True, description = "Script used to extract all users from Active Directory through LDAP(S)")
	parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address of DC>')
	parser.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')


	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)


	options = parser.parse_args()
	domain, username, password, address = parse_target(options.target)

	if domain is None:
		domain = ''
	if password == '' and username != '' and options.hashes is None :
		from getpass import getpass
		password = getpass("Password:")
	if options.hashes is not None:
		lmhash, nthash = options.hashes.split(':')
	else:
		lmhash = ''
		nthash = ''



	# try to connect to ldap
	try:
		# Create the baseDN
		domainParts = domain.split('.')
		baseDN = ''
		for i in domainParts:
			baseDN += 'dc=%s,' % i
		# Remove last ','
		baseDN = baseDN[:-1]

		
		print("Testing LDAP connection on "+str(baseDN)+"...")
		ldapConnection = ldap.LDAPConnection('ldap://%s' % options.target, baseDN, address)
		ldapConnection.login(username, password, domain, lmhash, nthash)
		print("LDAP connection successfull without encryption.")
	except ldap.LDAPSessionError as e:
		if str(e).find('strongerAuthRequired') >= 0:
			try:
				# We need to try SSL
				ldapConnection = ldap.LDAPConnection('ldaps://%s' % options.target, baseDN, address)
				ldapConnection.login(username, password, domain, lmhash, nthash)
				print("LDAP connection successfull with SSL encryption.")
			except:
				ldapConnection.close()
				print("Error : Could not connect to ldap.")
				import traceback
				traceback.print_exc()
		else:
			ldapConnection.close()
			print("Error : Could not connect to ldap.")
			import traceback
			traceback.print_exc()



	# catch all users in domain or just the specified one
	searchFilter = "(&(objectCategory=person)(objectClass=user))"
	users_list = []
	try:
		print("Retrieving user objects in LDAP directory...")
		ldap_users = ldapConnection.search(searchFilter=searchFilter, attributes=['sAMAccountName', 'objectSID'])
		print("Converting ObjectSID in string SID...")
		for user in ldap_users:
			try:
				ldap_username = str( str(user[1]).split("vals=SetOf:")[2] ).strip()
				sid = str( str( str(user[1]).split("vals=SetOf:")[1]).split("PartialAttribute")[0] ).strip()[2:]
				# convert objectsid to string sid
				binary_string = binascii.unhexlify(sid)
				version = struct.unpack('B', binary_string[0:1])[0]
				authority = struct.unpack('B', binary_string[1:2])[0]
				sid_string = 'S-%d-%d' % (version, authority)
				binary_string = binary_string[8:]
				for i in range(authority):
					value = struct.unpack('<L', binary_string[4*i:4*(i+1)])[0]
					sid_string += '-%d' % value
				name_and_sid = [ldap_username.strip(), sid_string]
				
				users_list.append( name_and_sid )
			except:
				pass 
				# some users may not have samAccountName
		print("Found about " + str( len(users_list) ) + " users in LDAP directory :\n")
		for user in users_list:
			print(user)
		print("\n")
	except ldap.LDAPSearchError as e:
		if e.getErrorString().find('sizeLimitExceeded') >=0:
			print(e)
			ldap_users = e.getAnswers()
			pass # LDAP results limit reached
		else:
			raise
	except:
		ldapConnection.close()
		print("Error : Could not extract users from ldap.")
		import traceback
		traceback.print_exc()

	if len(users_list) == 0:
		print("No user found in LDAP directory")
		sys.exit(1);







if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		os._exit(1)
