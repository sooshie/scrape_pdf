A basic script based that uses PDFMiner to decompress streams, and then looks inside the streams

Currently it attempts to pull out IPs, hashes, URLs, and hostnames.

Requires:

* pip install dnspython
* grab uniaccept from <a href="https://github.com/icann/uniaccept-python">here</a>
* pip install pdfminer


Then after you've done that, you'll likely want to get the newest TLD list.<br/>
Open a Python interpreter then:<br/>

```
import uniaccept
uniaccept.refreshtlddb("/tmp/tld-list.txt")
```
Feel free to change the location of the tld-list.txt file, the scrape-pdf.py script expects it in the CWD.


