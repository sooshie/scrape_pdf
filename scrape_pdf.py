import re
import sys
import mmap
import string
import uniaccept
from pdfminer.pdfpage import PDFPage
from pdfminer.layout import LAParams
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter
from pdfminer.converter import XMLConverter, HTMLConverter, TextConverter

def main(argv):
    #codec = 'utf-8'
    codec = 'ascii'
    laparams = LAParams()
    pagenos = set()
    maxpages = 0
    password = ''
    caching = True
    rotation = 0
    rsrcmgr = PDFResourceManager(caching=caching)

    # Do a double read thanks to:
    # https://mail.python.org/pipermail/python-list/2009-April/531944.html
    mm = mmap.mmap(-1, 1024*1024*1024)

    device = TextConverter(rsrcmgr, mm, codec=codec, laparams=laparams, imagewriter=None)

    fname = argv[1]
    fp = file(fname, 'rb')
    interpreter = PDFPageInterpreter(rsrcmgr, device)
    for page in PDFPage.get_pages(fp, pagenos,
                                  maxpages=maxpages, password=password,
                                  caching=caching, check_extractable=True):
        page.rotate = (page.rotate+rotation) % 360
        interpreter.process_page(page)
    fp.close()

    eof = mm.tell()
    device.close()
    mm.close()

    # Recreate the mmap area w/the correct size
    mm = mmap.mmap(-1, eof)

    device = TextConverter(rsrcmgr, mm, codec=codec, laparams=laparams, imagewriter=None)

    fname = argv[1]
    fp = file(fname, 'rb')
    interpreter = PDFPageInterpreter(rsrcmgr, device)
    for page in PDFPage.get_pages(fp, pagenos,
                                  maxpages=maxpages, password=password,
                                  caching=caching, check_extractable=True):
        page.rotate = (page.rotate+rotation) % 360
        interpreter.process_page(page)
    fp.close()

    mm.seek(0)

    ip_regex = re.compile(r'((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))')
    hash_regex = re.compile(r'(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})') # md5, sha1, sha256
    url_regex = re.compile(r'\b((?:[\w-]+://?|www[.])[A-Za-z0-9-_\/.%?=&\[\]()@!$#,;]+)', re.MULTILINE)
    hostname_regex = re.compile(r'([a-zA-Z\d-]{,63}(?:\.[a-zA-Z\d-]{,63}|\s\.\s[a-zA-Z\d-]{,63})+)', re.MULTILINE)
    single_line_hostname_regex = re.compile(r'([a-zA-Z\d-]{,63}(?:\.[a-zA-Z\d-]{,63}|\s\.\s[a-zA-Z\d-]{,63})+)')
    doc = ''
    while True:
        if mm.tell() >= eof: 
            break
        doc += mm.readline().rstrip()
    
    m = re.findall(ip_regex, doc)
    if m != None and len(m) > 0: print set(m)
    m = re.findall(url_regex, doc)
    if m != None and len(m) > 0: print set(m)
    m = re.findall(hash_regex, doc)
    if m != None and len(m) > 0: print set(m)
    m = re.findall(hostname_regex, doc)
    hostname_candidates = []
    if m != None and len(m) > 0: hostname_candidates = list(set(m))
    m = re.findall(single_line_hostname_regex, doc)
    if m != None and len(m) > 0: hostname_candidates = list(set(m + hostname_candidates))

    if len(hostname_candidates) > 0:
        for h in hostname_candidates:
            domain = string.replace(h, ' ', '')
            #print h
            if uniaccept.verifytldoffline(domain, "./tld-list.txt") and domain[-1] != '.':
                print h

    #print doc
    device.close()
    mm.close()

if __name__ == '__main__': sys.exit(main(sys.argv))
