#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of StalkPhish - see https://github.com/t4d/StalkPhish

import requests
import re
import socket
from os.path import dirname
from urllib.parse import urlparse, quote
from tools.utils import TimestampNow
from tools.utils import UAgent
from tools.utils import NetInfo


# siteURl
def SiteURLSQL(SearchString, line, LOG, SQL, TABLEname, PROXY, UAFILE, UAG):
    # remove URL containing UID-style strings
    siteURL = quote(re.split("(?:[0-9a-fA-F]:?){32}", line[0])[0], ':/')
    if siteURL.startswith('https:'):
        siteDomain = siteURL.split('/')[2]
    else:
        siteDomain = siteURL.split('/')[0]
        siteURL = "http://" + siteURL
    dn = dirname(siteURL)

    # Test if entry still exist in DB
    if SQL.SQLiteVerifyEntry(TABLEname, dn) is 0:
        # Proceed to informations retrieve
        now = str(TimestampNow().Timestamp())
        source_url = "https://urlquery.net/" + line[1]
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
                r = requests.get(siteURL, headers=user_agent, proxies=proxies, allow_redirects=True)
                # Follow redirect and add new URI to database
                if (len(r.history) > 1) and ("301" in str(r.history[-1])) and (siteURL != r.url) and (siteURL.split('/')[:-1] != r.url.split('/')[:-2]) and (siteURL + '/' != r.url):
                    lastHTTPcode = str(r.status_code)
                    SQL.SQLiteInsertPK(TABLEname, r.url, siteDomain, IPaddress, source_url, now, lastHTTPcode, ASN)
                else:
                    pass
                lastHTTPcode = str(r.status_code)
            except ValueError:
                # No user-agent configured
                r = requests.get(siteURL, proxies=proxies, allow_redirects=True)
                lastHTTPcode = str(r.status_code)
            except requests.exceptions.Timeout:
                lastHTTPcode = "timeout"
            except requests.exceptions.ConnectionError:
                lastHTTPcode = "aborted"
            except:
                lastHTTPcode = "---"
                pass
        except Exception as e:
            # Unknown status code
            LOG.error("Connection error: {}".format(e))
            pass

        # Add data into database
        LOG.info(siteURL + " " + siteDomain + " " + IPaddress + " " + source_url + " " + now + " " + lastHTTPcode)
        SQL.SQLiteInsertPK(TABLEname, siteURL, siteDomain, IPaddress, source_url, now, lastHTTPcode, ASN)

    else:
        LOG.debug("Entry still known: " + siteURL)
        pass


# Urlquery Web Search
# UrlQuery could 'drop' your GET if using Tor network
def UrlqueryOSINT(ConfURLQUERY_url, PROXY, SearchString, LOG):
    global HTMLText
    try:
        proxies = {'http': PROXY, 'https': PROXY}
        payload = {'q': SearchString}
        r = requests.get(ConfURLQUERY_url, params=payload, allow_redirects=True, timeout=(10, 20))
        HTMLText = r.text
        LOG.info("Searching for \'" + SearchString + "\'...")
    except Exception as e:
        LOG.error("Error while GETting HTML page: {}".format(e))


# Parse urlQuery HTML page
def UrlqueryExtractor(SearchString, LOG, SQL, TABLEname, PROXY, UAFILE):
    UAG = UAgent()
    # Search in Urlquery HTML file
    try:
        m = re.findall(r"<td><a title='(.*?)' href='(.*?)'>", HTMLText)
        for line in m:
            SiteURLSQL(SearchString, line, LOG, SQL, TABLEname, PROXY, UAFILE, UAG)
    except TypeError:
        pass

    except Exception as e:
        LOG.error("HTML parser Error: {}".format(e))
