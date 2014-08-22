#!/usr/bin/python
#----------------------------------------------------------------------#
# Batch/Mass/Multiple VirusTotal.com Uploader (BMMVTU.py) v0.1 (2011-09-30)
#---Important----------------------------------------------------------#
# Python 2.6+ & simplejson needs to be installed before hand           #
# Left a few debug commands & incomplete features in comments          #
#                                                                      #
#         *** Do NOT use this for illegal or malicious use ***         #
#             YOU are using this script at YOUR OWN RISK.              #
#This software is provided "as is" WITHOUT ANY guarantees OR warranty. #
#----------------------------------------------------------------------#
import getopt,hashlib,httplib,itertools,mimetypes,os,pprint,simplejson,sys,time,urlparse
#-----------------------------------------------------------------------
key = "                                                                "   # Make sure to set this to your VirusTotal.com public API key.
sleepTime = 30                                                             # VirusTotal.com only allows 20 requests every 5 miniutes.
retry = 3                                                                  # The number of times to retry when something fails/Times to wait in the queue.
separator = ","                                                            # "," is commonly used for CSV files. TAB (\t) works well for pasting into spreadsheets.
#-----------------------------------------------------------------------
# Is it a valid file (Is it a file & its size)
def check_file(filename):
   if not os.path.isfile(filename):
      print "[-] Error: '%s' is not a valid file" % filename
      fout.write("Error!" + separator + "not a valid file" + separator + filename + "\n")
      return False

   filesize = os.path.getsize(filename)
   if filesize < 1 or filesize > 20971519:
      print "[-] Error: Filesize (%s bytes)" % filesize
      fout.write("Error!" + separator + "Filesize is wrong" + separator + filename + "\n")
      return False
   return True

# Get the results from VirusTotal.com
def get_report(resource):
   json = post_multipart("https://www.virustotal.com/api/get_file_report.json", {'resource':resource, 'key':key})
   return simplejson.loads(json)

# Checks the server response for the API (blocked or wrong key)
def result_status(result,resource):
   while result == -2:                                                     # Exceeded the public API request rate
      print "[-] Error: Exceeded the public API request rate (Waiting 60 second)"
      time.sleep(60)                                                       # Wait a bit before re-trying
      data = get_report(resource)                                          # Check to see if MD5 is in the database
      result = data['result']

   if result == -1:                                                        # API key provided is incorrect
      print "[-] Error: The API key provided is incorrect"
      help()
      sys.exit(1)                                                          # Quit, because we can't go further
   return

# Request the file to VirusTotal.com
def send_file(filename):
   files = [('file', filename, open(filename, 'rb').read())]
   json = post_multipart("https://www.virustotal.com/api/scan_file.json", {'key':key}, files)
   return simplejson.loads(json)

# The magic/behind the scene stuff/Under the bonnet
def do_files(filenames):
   numFiles = len(filenames)
   count = 0
   for filename in filenames:                                              # Do every file
      try:                                                                 # Keep going even if we get an error
         count += 1
         print "[>] Scanning %s/%s (%s)" % (str(count),str(numFiles),filename)

         if check_file(filename) != True:
            continue

         md5sum = hashlib.md5(open(filename, 'rb').read()).hexdigest()     # Find the file's MD5 value
         data = get_report(md5sum)                                         # Check to see if MD5 is in the database
         result_status(data['result'],md5sum)                              # Check server response
         if data['result'] != 0:                                           # Not known to VirusTotal.com
            for _ in itertools.repeat(None, retry):                        # Try xxx times to upload
               print "[>] File not found. Submitting (%s)" % filename
               data = send_file(filename)                                  # Send the file to be scanned
               if data['result'] == 1:                                     # Have we successfully uploaded it?
                  break                                                    # Yes!
               else:                                                       # No!   Other? Fallback/Safey net
                  print "[-] Error: Submit failed (%s)" % filename   # + str(pprint.pprint(data))
                  time.sleep(sleepTime)                                    # Wait a bit before re-trying

            if data['result'] != 1:                                        # Result != 1 if upload wasn't successful
               print "[-] Failed: Didn't submit (%s)" % filename
               fout.write("Failed!" + separator + "Didn't submit" + separator + filename + "\n")
               continue                                                    # Move on to the next file

            for _ in itertools.repeat(None, retry):                        # Try xxx times to check
               for o in data:                                              # Read all the JSON objects
                  if o == "report":                                        # Does VirusTotal.com have a report..
                     break                                                 # ...Yes! So quit
                  elif o == "scan_id":                                     # ...No. Still scanning
                     scan_id = data['scan_id']                             # Use the new scan ID value, rather than the MD5
                     print "[>] Waiting 60 seconds for VirusTotal.com to finish scanning (%s)" % scan_id
                     time.sleep(60)                                        # Wait a bit before re-trying
                  elif data['result'] == 0:                                # ...No. Does VirusTotal.com know of it yet?
                     print "[>] Waiting in the queue"
                     time.sleep(sleepTime)                                 # Wait a bit before re-trying
               data = get_report(scan_id)                                  # Check to see if MD5 is in the database
               result_status(data['result'],scan_id)                       # Check server response

            if data['result'] != 1:                                        # Result != 1 if upload wasn't successful
               print "[-] Failed: VirusTotal.com is still scanning or a large queue. Try again later or increase 'retry' (%s)" % filename
               fout.write("Failed!" + separator + "still scanning or a large queue" + separator + filename + "\n")
               #retry_files.append(scan_id)
               continue

         if count < numFiles:                                              # If we are not using the last file....
            time.sleep(sleepTime)                                          # Sleep between requests so as not to overload VirusTotal.com

         report = data['report']
         permalink = data['permalink']
         #scan_id = permalink.split('=')[1]

         timeStamp = report[0]
         reportEntries = report[1]
         numEntries = len(reportEntries)

         numDetects = 0
         entryValues = dict.values(reportEntries)
         for v in entryValues:
            if v != u'':
               numDetects += 1

         output_string = md5sum + separator + timeStamp + separator + filename + separator + str(numEntries) + separator +str(numDetects) + separator
         for k,v in sorted(reportEntries.iteritems()):
            k = k.encode("ascii")
            v = v.encode("ascii")
            if v == "":
               v = "-"
            output_string += k + separator + v + separator

         output_string += permalink

         fout.write(output_string + "\n")
         #pprint.pprint(data['report'])

      except Exception as e:
         print "[-] Error [1]: ", e
         fout.write("Error!" + separator + str(e) + separator + filename + "\n")

# Perform an HTTP POST request
def post_multipart(url, fields, files=()):
   content_type, data = encode_multipart_formdata(fields, files)
   url_parts = urlparse.urlparse(url)
   if url_parts.scheme == 'http':
      h = httplib.HTTPConnection(url_parts.netloc)
   elif url_parts.scheme == 'https':
      h = httplib.HTTPSConnection(url_parts.netloc)
   path = urlparse.urlunparse(('', '') + url_parts[2:])
   h.request('POST', path, data, {'content-type':content_type})
   return h.getresponse().read()

# Encoding the request
def encode_multipart_formdata(fields, files=()):
   BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
   CRLF = '\r\n'
   L = []
   for key, value in fields.items():
      L.append('--' + BOUNDARY)
      L.append('Content-Disposition: form-data; name="%s"' % key)
      L.append('')
      L.append(value)
   for (key, filename, value) in files:
      L.append('--' + BOUNDARY)
      L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
      content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
      L.append('Content-Type: %s' % content_type)
      L.append('')
      L.append(value)
   L.append('--' + BOUNDARY + '--')
   L.append('')
   body = CRLF.join(L)
   content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
   return content_type, body

# Help screen
def help():
   print "\n\nAbout:"
   print "  This is a Python script which makes use of VirusTotal.com's public API, to automate scanning multiple files."
   print "  To use this you will need a \"API key\" from VirusTotal.com (Free signup).\n\n"
   print "bmmvtu.py --output <outputfile> <evil1 evil2="" evil3...="">\n"
   print "Arguments:"
   print "  -o --output      Path of the file to write output to"
   print "  -h --help        Prints this help message\n\n"
   print "Example:"
   print "  bmmvtu.py -o results.csv evil1.exe evil2.exe"
   print "  bmmvtu.py --output results.txt folder/*\n"
#-----------------------------------------------------------------------
#print "[*] Batch/Mass/Multiple VirusTotal.com Uploader (BMMVTU) v0.1 (2011-09-30)"

# Process arguments
opts, args = getopt.getopt(sys.argv[1:], "o:h", ["output=", "help"])
for o, a in opts:
   if o in ('-o', '--output'):
#      outputFileName = a
      outputFileName = '/home/montanor/Desktop/virustotal/raw.csv'
#      a = '/home/montanor/Desktop/virustotal/raw.csv'
   elif o in ('-h', '--help'):
      help()
      sys.exit(1)
   else:
      pass

# Check for valid number of arguments
#if len(sys.argv) < 4:
#   print "[-] Error: Invalid number of arguments"
#   help()
#   sys.exit(1)

# Check for API key
if len(key) != 64:
   print "[-] Error: Please provide a valid API key"
   help()
   sys.exit(1)

# Check the wait time
if sleepTime < 15:
   print "[!] Warning: Its recommended to wait at least 15 seconds between requests"

   if len(args) > 20:
      print "[!] Warning: You will quickly max out your API request rate"

try:
   fout = open(outputFileName, "w")
   fout.write("md5sum" + separator + "Time Stamp" + separator + "Filename" + separator + "Total AVs" + separator + "Detections" + separator + "Permalink\n")

   #retry_files = list()                                                    # Retry these files (e.g. still waiting to be scanned)
   do_files(args)
   #do_files(retry_files)

   fout.close()

except Exception as e:
   print "[-] Error [0]: ", e

print "[*] Done!"

