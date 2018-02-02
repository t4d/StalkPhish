#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of StalkPhish - see https://github.com/t4d/StalkPhish

import requests
import os
import re
import getopt
import sys
import json
import hashlib
import socket
import zipfile
import warnings
import sqlite3
from os.path import dirname
from urllib.parse import urlparse
from tools.utils import TimestampNow
from tools.utils import VerifyPath
from tools.utils import SHA256
from tools.utils import UAgent
from tools.sqlite import SqliteCmd

# Connexion tests, Phishing kits downloadingd
def TryPKDownload(siteURL,siteDomain,IPaddress,TABLEname,InvTABLEname,DLDir,SQL,PROXY,LOG,UAFILE):
	proxies = {'http': PROXY, 'https': PROXY}
	UAG = UAgent()
	UA = UAG.ChooseUA(UAFILE)
	user_agent = {'User-agent': UA}
	now = str(TimestampNow().Timestamp())
	SHA = SHA256()

	# Cleaning siteURL before trying to download
	PsiteURL = None
	ResiteURL = dirname(siteURL)
	PsiteURL = urlparse(ResiteURL)
	if len(PsiteURL.path.split("/")[1:]) >= 2:
		siteURL = ResiteURL.rsplit('/', 1)[0]
	else:
		siteURL = ResiteURL

	# Let's try to find a phishing kit source archive
	try:
		r = requests.get(siteURL, headers=user_agent, proxies=proxies, allow_redirects=True, timeout=(5,12))
		LOG.info("["+str(r.status_code)+"] "+r.url)

		if (str(r.status_code) == "200") or (str(r.status_code) == "403"):
			SQL.SQLiteInsertStillTryDownload(TABLEname, siteURL)
			if SQL.SQLiteInvestigVerifyEntry(InvTABLEname, siteDomain, IPaddress) is 0:
				SQL.SQLiteInvestigInsert(InvTABLEname, siteURL, siteDomain, IPaddress, now, str(r.status_code))

			else:
				pass
			ziplist = []
			path = siteURL
			pathl = '/' .join(path.split("/")[:3])
			pathlist = path.split("/")[3:]

			# Make list
			current=0
			newpath=""
			while current < len(pathlist):
				if current == 0:
					newpath = pathlist[current]
				else:
					newpath = newpath+"/"+pathlist[current]
				current = current + 1
				pathD = pathl+"/"+newpath
				ziplist.append(pathD)

			try:
				# Try too find and download phishing kit archive (.zip)
				if len(ziplist) > 1:
					for zip in ziplist:
						if ('=' or '%' or '?' or '-' or '@' or '.') not in os.path.basename(os.path.normpath(zip)):
							if ('/') not in zip[-1:] and ('.') not in zip[-3:]:
								try:
									LOG.info("trying "+zip+".zip")
									rz = requests.get(zip+".zip", headers=user_agent, proxies=proxies, allow_redirects=True, timeout=(5,12))
									if str(rz.status_code) != "404":
										lastHTTPcode = str(rz.status_code)
										zzip = zip.replace('/', '_').replace(':', '')
										if "application/zip" in rz.headers['content-type'] or "application/octet-stream" in rz.headers['content-type']:
											savefile=DLDir+zzip+'.zip'
											# Still collected file
											if os.path.exists(savefile):
												LOG.info("[DL ] Found still collected archive: "+savefile)
												return
											# New file to download
											else:
												LOG.info("[DL ] Found archive, downloaded it as: "+savefile)
												with open(savefile, "wb") as code:
													code.write(rz.content)
													pass
												ZipFileName = str(zzip+'.zip')
												ZipFileHash = SHA.hashFile(savefile)
												SQL.SQLiteInvestigUpdatePK(InvTABLEname,siteURL,ZipFileName,ZipFileHash,now,lastHTTPcode)
												return
										else:
											pass
									# 404
									else:
										pass
								except:
									err = sys.exc_info()
									LOG.error("Error: " + str(err))
									print("Error: " + str(err))
									pass
							else:
								pass
						else:
							pass
					else:
						pass
				# Ziplist empty
				else:
					pass
			except:
				pass

		elif str(r.status_code) == "404":
			lastHTTPcode = str(r.status_code)
			SQL.SQLiteInvestigUpdateCode(InvTABLEname, siteURL, now, lastHTTPcode)
			SQL.SQLiteInsertStillTryDownload(TABLEname, siteURL)
		else:
			lastHTTPcode = str(r.status_code)
			SQL.SQLiteInvestigUpdateCode(InvTABLEname, siteURL, now, lastHTTPcode)

	except requests.exceptions.ConnectionError:
		SQL.SQLiteInvestigUpdateCode(InvTABLEname, siteURL, now, 'Err')
		LOG.debug("Connection error: "+siteURL)

	except requests.exceptions.ConnectTimeout:
		SQL.SQLiteInvestigUpdateCode(InvTABLEname, siteURL, now, 'To')
		LOG.debug("Connection Timeout: "+siteURL)

	except requests.exceptions.ReadTimeout:
		SQL.SQLiteInvestigUpdateCode(InvTABLEname, siteURL, now, 'RTo')
		LOG.debug("Connection Read Timeout: "+siteURL)

	except requests.exceptions.MissingSchema:
		SQL.SQLiteInvestigUpdateCode(InvTABLEname, siteURL, now, 'Err')
		LOG.debug("Malformed URL, skipping: "+siteURL+"\n")

	except:
		err = sys.exc_info()
		LOG.error("Error: " + str(err))
