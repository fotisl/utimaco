#!/usr/bin/env python

import sys

f = open(sys.argv[1], 'r')
header = f.read(128)

if header[:4] != 'MTCH':
    print 'Invalid MTC file!'
    f.close()
    sys.exit(1)

print 'Module name: %s' % (header[44:59].strip('\x00'))
v = '.'.join(['%i' % (ord(header[i])) for i in xrange(60, 64)])
print 'Module version: %s' % (v)
print 'Module description: %s' % (header[64:96].strip('\x00'))

f2 = open(sys.argv[2], 'w')
f2.write(f.read())
f.close()
f2.close()
