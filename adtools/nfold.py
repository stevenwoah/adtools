################################################################################ 
# Copyright (C) 1998 by the FundsXpress, INC.
#
# All rights reserved.
#
# Export of this software from the United States of America may require
# a specific license from the United States Government.  It is the
# responsibility of any person or organization contemplating export to
# obtain such a license before exporting.
#
# WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
# distribute this software and its documentation for any purpose and
# without fee is hereby granted, provided that the above copyright
# notice appear in all copies and that both that copyright notice and
# this permission notice appear in supporting documentation, and that
# the name of FundsXpress. not be used in advertising or publicity pertaining
# to distribution of the software without specific, written prior
# permission.  FundsXpress makes no representations about the suitability of
# this software for any purpose.  It is provided "as is" without express
# or implied warranty.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
# WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
################################################################################ 
# Ported to Python by Steven O'Donnell
################################################################################ 

def krb5int_nfold(string, width):
	'''
	n-fold(k-bits):
	l = lcm(n,k)
	r = l/k
	s = k-bits | k-bits rot 13 | k-bits rot 13*2 | ... | k-bits rot 13*(r-1)
	compute the 1's complement sum:
	n-fold = s[0..n-1]+s[n..2n-1]+s[2n..3n-1]+..+s[(k-1)*n..k*n-1]
	'''

	string_len = len(string)
	string_byte_arr = [ ord(x) for x in string ]

	a = width 
	b = string_len

	while b != 0:
		c = b
		b = a % b
		a = c

	lcm = string_len * width / a

	out = [ 0 for x in xrange(0, width) ]
	byte = 0

	i = lcm - 1
	while i >= 0:
		msbit = (
				( ( string_len << 3 ) - 1 ) +
				( ( ( string_len << 3 ) + 13 ) * ( i / string_len ) ) +
				( ( string_len - ( i % string_len ) ) << 3 )
				) % ( string_len << 3 )
		byte += (
					(
						( string_byte_arr[ ( ( string_len - 1 ) - ( msbit >> 3 ) ) % string_len ] << 8 ) |
						( string_byte_arr[ ( ( string_len) - ( msbit >> 3 ) ) % string_len ] )
					) >> ( ( msbit & 7 ) + 1 )
				) & 0xff
		byte += out[ i % width ]
		out[ i % width ] = byte & 0xff

		byte = byte >> 8

		i -= 1

	if  byte:
		i = width - 1
		while i >= 0:
			byte += out[i]
			out[i] = byte & 0xff

			byte = byte >> 8

			i -= 1

	return "".join([ chr(x) for x in out ])

