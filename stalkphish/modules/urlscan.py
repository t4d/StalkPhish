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
def SiteURLSQL(item, LOG, SQL, TABLEname, PROXY, UAFILE, UAG):
    # remove URL containing UID-style strings
    siteURL = quote(re.split("(?:[0-9a-fA-F]:?){32}", item['page']['url'])[0], ':/')
    dn = dirname(siteURL)

    # Test if entry still exist in DB
    if SQL.SQLiteVerifyEntry(TABLEname, dn) == 0:
        now = str(TimestampNow().Timestamp())
        siteDomain = urlparse(item['page']['url']).netloc
        source_url = item['result'].replace("/api/v1", "")
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

        LOG.info(siteURL + " " + siteDomain + " " + IPaddress + " " + source_url + " " + now + " " + lastHTTPcode)
        SQL.SQLiteInsertPK(TABLEname, siteURL, siteDomain, IPaddress, source_url, now, lastHTTPcode, ASN)

    else:
        LOG.debug("Entry still known: " + siteURL)
        pass


# Urlscan Web Search
def UrlscanOSINT(ConfURLSCAN_apikey, ConfURLSCAN_url, PROXY, SearchString, LOG):
    global HTMLText
    try:
        proxies = {'http': PROXY, 'https': PROXY}
        payload = {'q': SearchString}
        headers = {}
        if ConfURLSCAN_apikey:
            headers = {'API-Key': '{}'.format(ConfURLSCAN_apikey)}

        r = requests.get(url=ConfURLSCAN_url + "?q=page.url:" + SearchString + " OR page.domain:" + SearchString, headers=headers, proxies=proxies, allow_redirects=True, timeout=(10, 20))
        HTMLText = r.json()
        LOG.info("Searching for \'" + SearchString + "\'...")

    except requests.exceptions.ConnectTimeout as e:
        LOG.error("Error while connecting to urlscan.io: {}".format(e))
        pass
    except Exception as e:
        LOG.error("Urlscan connection error: {}".format(e))
        pass


# Parse Urlscan HTML page
def UrlscanExtractor(LOG, SQL, TABLEname, PROXY, UAFILE):
    UAG = UAgent()
    # Search in Urlscan HTML file
    try:
        for item in HTMLText['results']:
            SiteURLSQL(item, LOG, SQL, TABLEname, PROXY, UAFILE, UAG)
    except TypeError:
        pass

    except Exception as e:
        LOG.error("HTML parser Error: {}".format(e))
