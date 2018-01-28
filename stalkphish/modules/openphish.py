#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of StalkPhish - see https://github.com/t4d/StalkPhish

import os
import re
import sys
import time
import socket
import sqlite3
import logging
import requests
from urllib.parse import urlparse
from tools.utils import TimestampNow
from tools.utils import UAgent
from tools.sqlite import SqliteCmd

## Openphish (Community)
def OpenphishOSINT(openphish_file,ConfOPENPHISH_url,ConfOPENPHISH_keep,SrcDir,PROXY,LOG):
	# Get Openphish OSINT TXT file
	proxies = {'http': PROXY, 'https': PROXY}
	LOG.info("Retrieving OpenPhish\'s file ("+ConfOPENPHISH_url+") ... Could take several minutes...")
	resp = requests.get(url=ConfOPENPHISH_url, proxies=proxies, allow_redirects=True)
	with open(openphish_file,"wb") as file:
		file.write(resp.content)
		LOG.info("OpenPhish\'s file retrieved and save as "+openphish_file)

## Data extraction
def OpenphishExtractor(openphish_file,SearchString,LOG,SQL,TABLEname,PROXY,UAFILE):
	UAG = UAgent()
	with open(openphish_file,"rt") as txt:
		for entry in txt:
			## Search
			if SearchString in entry:
				# remove URL containing UID-style strings
				#siteURL = entry.rstrip()
				siteURL = re.split("(?:[0-9a-fA-F]:?){32}", entry.rstrip())[0]

				## Test if entry still exist in DB
				if SQL.SQLiteVerifyEntry(TABLEname, siteURL) is 0:
					now=str(TimestampNow().Timestamp())
					siteDomain=urlparse(entry).netloc
					source_url=openphish_file
					try:
						IPaddress=socket.gethostbyname(siteDomain)
					# can't resolv
					except:
						IPaddress=""

					# HTTP connection
					try:
						proxies = {'http': PROXY, 'https': PROXY}
						UA = UAG.ChooseUA(UAFILE)
						user_agent = {'User-agent': UA}
						try:
							r = requests.get(siteURL, headers=user_agent, proxies=proxies, allow_redirects=True, timeout=(5,12))
							lastHTTPcode = str(r.status_code)
						except ValueError:
							# No user-agent configured
							r = requests.get(siteURL, proxies=proxies, allow_redirects=True, timeout=(5,12))
							lastHTTPcode = str(r.status_code)
						except requests.exceptions.Timeout:
							lastHTTPcode = "timeout"
						except requests.exceptions.ConnectionError:
							lastHTTPcode = "aborted"
						except:
							lastHTTPcode = "---"
							err = sys.exc_info()
							LOG.error("HTTP error: " + str(err))
							pass
					except:
						# Unknown status code
						err = sys.exc_info()
						LOG.error("Connection error: " + str(err))
						pass

					# Add data into database
					LOG.info(siteURL)
					SQL.SQLiteInsertPK(TABLEname, siteURL, siteDomain, IPaddress, source_url, now, lastHTTPcode)

				else:
					LOG.debug("Entry still known: "+siteURL)
					pass
			else:
				pass

## Delete OpenPhish downloaded file, or not
def DeleteOpenphishFile(openphish_file,LOG):
	## Delete openphish_file
	try:
		os.remove(openphish_file)
		LOG.info("File "+openphish_file+" deleted.")
	except:
		LOG.error("Can't delete "+openphish_file+" !!!")
		pass
