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

## Data extraction
def AddUniqueURL(URLadd,LOG,SQL,TABLEname,PROXY,UAFILE):
	UAG = UAgent()
	# add schema 
	if not URLadd.startswith("http(|s)://") :
		URLadd="http://{}".format(URLadd)
	else:
		pass
	# remove URL containing UID-style strings
	siteURL = re.split("(?:[0-9a-fA-F]:?){32}", URLadd.rstrip())[0]
	## Test if entry still exist in DB
	if SQL.SQLiteVerifyEntry(TABLEname, siteURL) is 0:
		now=str(TimestampNow().Timestamp())
		siteDomain=urlparse(URLadd).netloc
		source_url=""
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
		LOG.info("Entry still known: "+siteURL)
		pass