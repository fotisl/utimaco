#!/usr/bin/env python

import sys
import struct
from collections import namedtuple
from operator import itemgetter
import time

class FileHdr(namedtuple('FileHdr', 'magic,nscns,timdat,symptr,nsyms,opthdr,flags,target_id')):
    structfmt = '<HHLLLHHH'
    structlen = struct.calcsize(structfmt)

    def __str__(self):
        s = 'Magic: %04x\n' % (self.magic)
        s = s + 'Number of sections: %u\n' % (self.nscns)
        s = s + 'Time: %s\n' % (time.asctime(time.localtime(self.timdat)))
        s = s + 'Pointer to symbol table: %u\n' % (self.symptr)
        s = s + 'Number of symbols: %u\n' % (self.nsyms)
        s = s + 'Size of optional header: %u\n' % (self.opthdr)
        s = s + 'Flags: 0x%04x\n' % (self.flags)
        s = s + 'Target ID: 0x%04x\n' % (self.target_id)
        return s

class OptHdr(namedtuple('OptHdr', 'magic,vstamp,tsize,dsize,bsize,entry,text_start,data_start')):
    structfmt = '<HHLLLLLL'
    structlen = struct.calcsize(structfmt)

    def __str__(self):
        s = 'Magic: %04x\n' % (self.magic)
        s = s + 'Linker version: %04x\n' % (self.vstamp)
        s = s + 'Text section size: %u\n' % (self.tsize)
        s = s + 'Data section size: %u\n' % (self.dsize)
        s = s + 'Uninitialized data section size: %u\n' % (self.bsize)
        s = s + 'Entry point: 0x%08x\n' % (self.entry)
        s = s + 'Text start: 0x%08x\n' % (self.text_start)
        s = s + 'Data start: 0x%08x\n' % (self.data_start)
        return s

class SecHdr(namedtuple('SecHdr', 'orig_name,paddr,vaddr,size,scnptr,relptr,lnnoptr,nreloc,nlnno,flags,reserved,page')):
    structfmt = '<8sLLLLLLLLLHH'
    structlen = struct.calcsize(structfmt)

    @property
    def name(self):
        return self.orig_name.rstrip('\x00')

    def __str__(self):
        s = 'Section \'%s\':\n' % (self.name)
        s = s + '\tPhysical address: 0x%08x\n' % (self.paddr)
        s = s + '\tVirtual address: 0x%08x\n' % (self.vaddr)
        s = s + '\tSize: %u\n' % (self.size)
        s = s + '\tFile pointer to raw data: %u\n' % (self.scnptr)
        s = s + '\tFile pointer to relocation: %u\n' % (self.relptr)
        s = s + '\tFile pointer to line numbers: %u\n' % (self.lnnoptr)
        s = s + '\tNumber of relocation entries: %u\n' % (self.nreloc)
        s = s + '\tNumber of line number entries: %u\n' % (self.nlnno)
        s = s + '\tFlags: 0x%08x\n' % (self.flags)
        s = s + '\tReserved: 0x%04x\n' % (self.reserved)
        s = s + '\tPage: %u\n' % (self.page)
        return s

class RelocHdr(namedtuple('RelocHdr', 'vaddr,symndx,reserved,type')):
    structfmt = '<LLHH'
    structlen = struct.calcsize(structfmt)

    def __str__(self):
        s = 'Virtual address: 0x%08x\n' % (self.vaddr)
        s = s + 'Index in symtab: %i\n' % (self.symndx)
        s = s + 'Reserved: 0x%04x\n' % (self.reserved)
        s = s + 'Type: 0x%04x\n' % (self.type)
        return s

class SymentHdr(namedtuple('SymentHdr', 'orig_name,value,scnum,type,sclass,numaux')):
    structfmt = '<8sLHHBB'
    structlen = struct.calcsize(structfmt)

    @property
    def name(self):
        if struct.unpack('II', self.orig_name)[0] == 0:
            return None
        else:
            return self.orig_name.rstrip('\x00')

    @property
    def offset(self):
        data = struct.unpack('II', self.orig_name)
        if data[0] != 0:
            return -1
        else:
            return data[1]

    def __str__(self):
        if self.name is not None:
            s = 'Symbol with name \'%s\':\n' % (self.name)
        else:
            s = 'Symbol with name offset %u:\n' % (self.offset)
        s = s + '\tValue: 0x%08x\n' % (self.value)
        s = s + '\tSection number: %u\n' % (self.scnum)
        s = s + '\tType: %x\n' % (self.type)
        s = s + '\tLoader class: %u\n' % (self.sclass)
        s = s + '\tNumber of auxiliary entries: %u\n' % (self.numaux)
        return s

class Coff:
    def __init__(self, f):
        if isinstance(f, basestring):
            self.f = open(f, 'r')
        else:
            self.f = f

        self.filehdr = self.readstruct(FileHdr)
        if self.filehdr.opthdr != 0:
            self.opthdr = self.readstruct(OptHdr)
        self.sechdr = [self.readstruct(SecHdr) for _ in range(self.filehdr.nscns)]

        self.reloc = {}
        relocsecs = [(s.name, s.relptr, s.nreloc) for s in self.sechdr if s.relptr != 0]

        for rs in relocsecs:
            self.f.seek(rs[1], 0)
            self.reloc[rs[0]] = [self.readstruct(RelocHdr) for _ in range(rs[2])]

        self.f.seek(self.filehdr.symptr, 0)
        self.symbols = [self.readstruct(SymentHdr) for _ in range(self.filehdr.nsyms)]

        baseoff = self.f.tell()
        nstrs = struct.unpack('I', self.f.read(4))[0]
        self.strings = []
        while True:
            s = ''
            off = self.f.tell() - baseoff
            if off >= nstrs:
                break
            b = self.f.read(1)
            while b != '' and b != '\x00':
                s = s + b
                b = self.f.read(1)
            self.strings.append((off, s))

    def __str__(self):
        s = 'File Header\n'
        s = s + str(self.filehdr)
        if self.filehdr.opthdr != 0:
            s = s + 'Optional header\n'
            s = s + str(self.opthdr)

        s = s + 'Sections\n'
        for sec in self.sechdr:
            s = s + str(sec)

        for rs in self.reloc.keys():
            s = s + 'Relocations for section %s\n' % (rs)
            for r in self.reloc[rs]:
                s = s + str(r)

        s = s + 'Symbols\n'
        for smb in self.symbols:
            s = s + str(smb)

        s = s + 'Strings:\n'
        for off, st in self.strings:
            s = s + 'Offset: %u Strings: \'%s\'\n' % (off, st)
        return s

    def readstruct(self, structtype):
        hdr = self.f.read(structtype.structlen)
        if len(hdr) != structtype.structlen:
            raise EOFError

        return structtype(*struct.unpack(structtype.structfmt, hdr))

    def sectiondata(self, sname):
        for s in self.sechdr:
            if s.name == sname:
                self.f.seek(s.scnptr, 0)
                return self.f.read(s.size)
        return None

    def symboldata(self, symbol):
        sec = self.sechdr[symbol.scnum - 1]
        self.f.seek(sec.scnptr + symbol.value - sec.vaddr, 0)
        nextsymb = 0xffffffff
        for smb in self.symbols:
            if smb.type != 4:
                continue
            if smb.value > symbol.value and smb.value < nextsymb:
                nextsymb = smb.value
        return self.f.read(nextsymb - symbol.value)

coff = Coff(sys.argv[1])

symbols = sorted([s for s in coff.symbols if s.type == 4 and s.scnum == 2], key=itemgetter(1))
idx = 1
for s in symbols:
    name = None
    if s.name is not None:
        name = s.name
    else:
        for off, st in coff.strings:
            if off == s.offset:
                name = st
    if name is None:
        name = 'unknown%i' % (idx)
        idx += 1
    print 'Doing symbol ' + name
    f = open('func/' + name, 'w')
    f.write(coff.symboldata(s))
    f.close()

