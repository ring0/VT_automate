#!/usr/bin/python

import sys 
import os 
import subprocess
import time, datetime, os

today = datetime.date.today()  # get today's date as a datetime type
todaystr = today.isoformat()   # get string representation: YYYY-MM-DD
                               # from a datetime type.
os.mkdir('/nsm/bro/vt_scan/todaystr)

if not os.path.exists('/nsm/bro/vt_scan/tmp/'):
    os.makedirs(todaystr)
