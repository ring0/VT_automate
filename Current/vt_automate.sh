#! /bin/bash

#cleanup from any previous scans
#rm -rf /nsm/bro/vt_scan/working/raw.csv
#rm -rf /nsm/bro/vt_scan/working/raw1.csv
#rm -rf /nsm/bro/vt_scan/working/corrected.csv


#Create directory using date as direcotry name
time_stamp=$(date +%Y_%m_%d)
mkdir -p /nsm/bro/vt_scan/tmp/
mkdir -p /nsm/bro/vt_scan/archive/files/"${time_stamp}$1"/
#mkdir -p /nsm/bro/vt_scan/debug/"${time_stamp}$1"/ #uncomment for debug files


#Move extracted files to folder and remove duplucates based on md5
mv -v /nsm/bro/extracted/* /nsm/bro/vt_scan/tmp/
python dedup.py /nsm/bro/vt_scan/tmp/

#Perform scanning
python bulk_vt_scanner.py --output /nsm/bro/vt_scan/archive/logs/raw.csv /nsm/bro/vt_scan/tmp/*
#cp /nsm/bro/vt_scan/tmp/raw.csv /nsm/bro/vt_scan/debug/"${time_stamp}$1"/raw_debug.csv #uncomment for debug files

#Move scanned files to archive location 
mv -v /nsm/bro/vt_scan/tmp/* /nsm/bro/vt_scan/archive/files/"${time_stamp}$1"/

#csv cleanup 
#sed -e 's!http[s]\?://!!g' /nsm/bro/vt_scan/working/raw.csv > /nsm/bro/vt_scan/working/raw1.csv #removes http(s):// from csv
#mv /nsm/bro/vt_scan/working/raw1.csv /nsm/bro/vt_scan/working/raw.csv
#python col_remove.py
sed -i 's/Emsisoft,\|GData,\|AVware,\|Zoner,\|Ad-Aware,\|AegisLab,\|AhnLab-V3,\|Antiy-AVL,\|International,\|CAT-QuickHeal,\|CMC,\|ClamAV,\|Commtouch,\|DrWeb,\|ESET-NOD32,\|F-Secure,\|Jiangmin,\|K7GW,\|Unwanted-File\|Kaspersky,\|McAfee,\|MicroWorld-eScan,\|NANO,\|Norman,\|Rising,\|SUPERAntiSpyware,\|Symantec,\|TotalDefense,\|Comodo,\|TrendMicro-HouseCall,\|Sophos,\|VBA32,\|Qihoo-360,\|VIPRE,\|K7AntiVirus,\|Fortinet,\|Ikarus,\|TheHacker,\|AVG,\|Agnitum,\|V3,\|Zillya,\|AntiVir,\|ViRobot,\|Avast,\|Baidu-International,\|( 6b49d2001 ),\|BitDefender,\|Bkav,\|ByteHero,\|F-Prot,\|Kingsoft,\|Malwarebytes,\|McAfee-GW-Edition,\|Microsoft,\|NANO-Antivirus,\|Panda,\|Tencent,\|WS.Reputation.1\|TrendMicro,\|nProtect\|,,//g' /nsm/bro/vt_scan/archive/logs/raw.csv && sed -i 's/-,/ /g' /nsm/bro/vt_scan/archive/logs/raw.csv && sed -i '/Error!\|Failed!/d' /nsm/bro/vt_scan/archive/logs/raw.csv && sed -i -r 's/(, *)+/, /g' /nsm/bro/vt_scan/archive/logs/raw.csv 

#Move report to webserver directory and archive csv 
cp  /nsm/bro/vt_scan/archive/logs/raw.csv /nsm/bro/vt_scan/archive/logs"${time_stamp}$1".csv
#sed -i '/md5sum/d' /nsm/bro/vt_scan/archive/logs/raw.csv 
python log_manager.py
awk '!x[$0]++' /var/www/vt/results.csv
#mv /nsm/bro/vt_scan/archive/logs/raw.csv /var/www/vt/results.csv
rm -rf /nsm/bro/vt_scan/tmp
sod01-admin@SOD01:/nsm/bro/vt_scan$
