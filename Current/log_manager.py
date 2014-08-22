#!/usr/bin/python

import sys 
import os 
import subprocess
import time, datetime, os

#today = datetime.date.today()  # get today's date as a datetime type
#todaystr = today.isoformat()   # get string representation: YYYY-MM-DD
                               # from a datetime type.
#os.mkdir('/nsm/bro/vt_scan/todaystr)

#if not os.path.exists('/nsm/bro/vt_scan/tmp/'):
#    os.makedirs(todaystr)


#subprocess.call("/nsm/bro/vt_scan/vt_automate.sh")
#subprocess.call("/nsm/bro/vt_scan/bulk_vt_scanner.py --output /nsm/bro/vt_scan/archive/logs/raw.csv /nsm/bro/vt_scan/tmp/*")

os.rename('/var/www/vt/results.csv', '/var/www/vt/results_tmp.csv')

filenames = ['/var/www/vt/results_tmp.csv', '/nsm/bro/vt_scan/archive/logs/raw.csv']
with open('/var/www/vt/results.csv', 'w') as outfile:
    for fname in filenames:
        with open(fname) as infile:
            for line in infile:
                outfile.write(line)


#os.remove('/nsm/bro/vt_scan/tmp')
