from distutils.core import setup

setup(
  name = 'adtools',
  packages = ['adtools'],
  version = '0.2',
  description = 'Active Directory toolset, including keytab generation',
  author = "Steven O'Donnell",
  author_email = 'developer@steven.io',
  url = 'https://github.com/stevenwoah/adtools',
  download_url = 'https://github.com/stevenwoah/adtools/archive/0.2.tar.gz',
  keywords = ['kerberos', 'keytab', 'gssapi', 'ldap', 'openldap', 'active', 'directory', 'ad', 'tools'],
  license = 'MIT',
  classifiers = [
      'Development Status :: 3 - Alpha',
      'Environment :: Console',
      'Intended Audience :: System Administrators',
      'License :: OSI Approved :: MIT License',
      'Operating System :: MacOS :: MacOS X',
      'Operating System :: POSIX :: Linux',
      'Programming Language :: Python :: 2',
      'Topic :: System :: Systems Administration',
      'Topic :: System :: Systems Administration :: Authentication/Directory'
    ],
  scripts = [
    "bin/adtools-join",
    ],
  install_requires = [
    "pycrypto >= 2.6.1",
    "python-ldap >= 2.4.22",
    "kerberos >= 1.2.5",
    ],
)
