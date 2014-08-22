#!/usr/bin/python

import csv

remove_from = 5 #Modify these as needed when new AV's are added to virus total
remove_to = 107 #Modify these as needed when new AV's are added to virus total

with open("/nsm/bro/vt_scan/working/raw.csv", "rb") as fp_in, open("/nsm/bro/vt_scan/working/corrected.csv", "wb") as fp_out:
    reader = csv.reader(fp_in, delimiter=",")
    writer = csv.writer(fp_out, delimiter=",")
    for row in reader:
        del row[remove_from:remove_to]
        writer.writerow(row)

