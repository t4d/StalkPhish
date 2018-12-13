#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of StalkPhish - see https://github.com/t4d/StalkPhish

import requests
import re
import sys
import socket
from os.path import dirname
from tools.utils import TimestampNow
from tools.utils import UAgent


# Urlquery Web Search
# UrlQuery could 'drop' your GET if using Tor network
def UrlqueryOSINT(ConfURLQUERY_url, PROXY, SearchString, LOG):
    global HTMLText
    try:
        proxies = {'http': PROXY, 'https': PROXY}
        payload = {'q': SearchString}
        r = requests.get(ConfURLQUERY_url, params=payload, proxies=proxies)
        HTMLText = r.text
        LOG.info("Searching for \'" + SearchString + "\'...")
    except:
        err = sys.exc_info()
        LOG.error("Error while GETting HTML page! " + str(err))


# Parse urlQuery HTML page
def UrlqueryExtractor(LOG, SQL, TABLEname, PROXY, UAFILE):
    UAG = UAgent()
    # Search in Urlquery HTML file
    try:
        m = re.findall(r"<td><a title = '(.*?)' href = '(.*?)'>", HTMLText)
        for line in m:
            # remove URL containing UID-style strings
            siteURL = re.split("(?:[0-9a-fA-F]:?){32}", line[0])[0]
            if siteURL.startswith('https:'):
                siteDomain = siteURL.split('/')[2]
            else:
                siteDomain = siteURL.split('/')[0]
                siteURL = "http://" + siteURL
            dn = dirname(siteURL)

            # Test if entry still exist in DB
            if SQL.SQLiteVerifyEntry(TABLEname, dn) is 0:

                # Proceed to informations retrieve
                source_url = "https://urlquery.net/" + line[1]

                try:
                    IPaddress = socket.gethostbyname(siteDomain)
                # can't resolv
                except:
                    IPaddress = ""

                now = str(TimestampNow().Timestamp())

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
                        pass
                except:
                    # Unknown status code
                    err = sys.exc_info()
                    LOG.error("Connection error: " + str(err))
                    pass

                LOG.info(siteURL + " " + siteDomain + " " + IPaddress + " " + source_url + " " + now + " " + lastHTTPcode)
                SQL.SQLiteInsertPK(TABLEname, siteURL, siteDomain, IPaddress, source_url, now, lastHTTPcode)

            else:
                LOG.debug("Entry still known: " + siteURL)
                pass

    except:
        err = sys.exc_info()
        LOG.error("HTML parser Error! " + str(err))
