#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of StalkPhish - see https://github.com/t4d/StalkPhish

import os
import re
import sys
import socket
import requests
from os.path import dirname
from urllib.parse import urlparse, quote
from tools.utils import TimestampNow
from tools.utils import UAgent
from tools.utils import NetInfo


# siteURl
def SiteURLSQL(phishingdb_file, entry, LOG, SQL, TABLEname, PROXY, UAFILE, UAG):
    siteURL = quote(re.split("(?:[0-9a-fA-F]:?){32}", entry.rstrip())[0], ':/')
    dn = dirname(siteURL)

    # Test if entry still exist in DB
    if SQL.SQLiteVerifyEntry(TABLEname, dn) is 0:
        now = str(TimestampNow().Timestamp())
        siteDomain = urlparse(entry).netloc
        source_url = phishingdb_file
        try:
            IPaddress = socket.gethostbyname(siteDomain)
            if IPaddress:
                rASN = NetInfo()
                ASN = rASN.GetASN(IPaddress).strip('\"')
            else:
                pass
        # can't resolv
        except:
            IPaddress = ""
            ASN = ""

        # HTTP connection
        try:
            proxies = {'http': PROXY, 'https': PROXY}
            UA = UAG.ChooseUA(UAFILE)
            user_agent = {'User-agent': UA}
            try:
                r = requests.get(siteURL, headers=user_agent, proxies=proxies, allow_redirects=True, timeout=(5, 12))
                # Follow redirect and add new URI to database
                if (len(r.history) > 1) and ("301" in str(r.history[-1])) and (siteURL != r.url) and (siteURL.split('/')[:-1] != r.url.split('/')[:-2]) and (siteURL + '/' != r.url):
                    lastHTTPcode = str(r.status_code)
                    SQL.SQLiteInsertPK(TABLEname, r.url, siteDomain, IPaddress, source_url, now, lastHTTPcode, ASN)
                else:
                    pass
                lastHTTPcode = str(r.status_code)
            except ValueError:
                # No user-agent configured
                r = requests.get(siteURL, proxies=proxies, allow_redirects=True, timeout=(5, 12))
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
        except Exception as e:
            # Unknown status code
            LOG.error("Connection error: {}".format(e))
            pass

        # Add data into database
        LOG.info(siteURL)
        SQL.SQLiteInsertPK(TABLEname, siteURL, siteDomain, IPaddress, source_url, now, lastHTTPcode, ASN)

    else:
        LOG.debug("Entry still known: " + siteURL)
        pass


# PhishingDB
def PhishingDBOSINT(phishingdb_file, ConfPHISHINGDB_url, ConfPHISHINGDB_keep, SrcDir, PROXY, LOG):
    # Get PhishingDB OSINT TXT file
    proxies = {'http': PROXY, 'https': PROXY}
    LOG.info("Retrieving Phishing.Database\'s file (" + ConfPHISHINGDB_url + ") ... Could take several minutes...")
    resp = requests.get(url=ConfPHISHINGDB_url, proxies=proxies, allow_redirects=True, timeout=(10, 20))
    with open(phishingdb_file, "wb") as file:
        file.write(resp.content)
        LOG.info("Phishing.Database\'s file retrieved and saved as " + phishingdb_file)


# Data extraction
def PhishingDBExtractor(phishingdb_file, SearchString, LOG, SQL, TABLEname, PROXY, UAFILE):
    UAG = UAgent()
    with open(phishingdb_file, "rt") as txt:
        for entry in txt:
            # Search
            if SearchString in entry:
                SiteURLSQL(phishingdb_file, entry, LOG, SQL, TABLEname, PROXY, UAFILE, UAG)
            else:
                pass


# Delete Phishing.Database downloaded file, or not
def DeletePhishingDBFile(phishingdb_file, LOG):
    # Delete phishingdb_file
    try:
        os.remove(phishingdb_file)
        LOG.info("File " + phishingdb_file + " deleted.")
    except:
        LOG.error("Can't delete " + phishingdb_file + " !!!")
        pass
