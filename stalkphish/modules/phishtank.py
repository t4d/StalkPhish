#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of StalkPhish - see https://github.com/t4d/StalkPhish

import re
import os
import sys
import json
import socket
import requests
from os.path import dirname
from urllib.parse import urlparse
from tools.utils import TimestampNow
from tools.utils import UAgent


# PhishTank
def PhishtankOSINT(phishtank_file, ConfPHISHTANK_url, ConfPHISHTANK_keep, SrcDir, PROXY, LOG):
    # Get phishtank OSINT JSON file
    proxies = {'http': PROXY, 'https': PROXY}
    LOG.info("Retrieving Phishtank JSON file (" + ConfPHISHTANK_url + ") ... Could take several minutes...")
    resp = requests.get(url=ConfPHISHTANK_url, proxies=proxies, allow_redirects=True)
    with open(phishtank_file, "wb") as file:
        file.write(resp.content)
        LOG.info("Phishtank\'s file retrieved. Proceeding to extraction...")


def PhishtankExtractor(phishtank_file, SearchString, LOG, SQL, TABLEname, PROXY, UAFILE):
    UAG = UAgent()
    # Search in Phishtank JSON file
    file = json.loads(open(phishtank_file).read())
    for entry in file:
        # Search
        if SearchString in entry['url']:
            # remove URL containing UID-style strings
            siteURL = re.split("(?:[0-9a-fA-F]:?){32}", entry['url'])[0]
            dn = dirname(siteURL)

            # Test if entry still exist in DB
            if SQL.SQLiteVerifyEntry(TABLEname, dn) is 0:

                IPaddress = entry['details'][0]['ip_address']
                source_url = entry['phish_detail_url']
                siteDomain = urlparse(entry['url']).netloc
                now = str(TimestampNow().Timestamp())
                try:
                    IPaddress = socket.gethostbyname(siteDomain)
                # can't resolv
                except:
                    IPaddress = ""

                # HTTP connection
                try:
                    proxies = {'http': PROXY, 'https': PROXY}
                    UA = UAG.ChooseUA(UAFILE)
                    user_agent = {'User-agent': UA}
                    try:
                        r = requests.get(siteURL, headers=user_agent, proxies=proxies, allow_redirects=True, timeout=(5, 12))
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
                except:
                    # Unknown status code
                    err = sys.exc_info()
                    LOG.error("Connection error: " + str(err))
                    pass
                LOG.info(siteURL)
                SQL.SQLiteInsertPK(TABLEname, siteURL, siteDomain, IPaddress, source_url, now, lastHTTPcode)

            else:
                LOG.debug("Entry still known: " + siteURL)
                pass
        else:
            pass


# Delete OpenPhish downloaded file, or not
def DeletePhishtankFile(phishtank_file, LOG):
    # Delete phishtank_file
    try:
        os.remove(phishtank_file)
        LOG.info("File " + phishtank_file + " deleted.")
    except:
        LOG.error("Can't delete " + phishtank_file + " !!!")
        pass
