#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of StalkPhish - see https://github.com/t4d/StalkPhish

import os
import sys
import requests
import re
import socket
import json
import cfscrape
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
    if SQL.SQLiteVerifyEntry(TABLEname, dn) is 0:
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
        except Exception as e:
            # Unknown status code
            LOG.error("Connection error: {}".format(e))
            pass

        LOG.info(siteURL + " " + siteDomain + " " + IPaddress + " " + source_url + " " + now + " " + lastHTTPcode)
        SQL.SQLiteInsertPK(TABLEname, siteURL, siteDomain, IPaddress, source_url, now, lastHTTPcode, ASN)

    else:
        LOG.debug("Entry still known: " + siteURL)
        pass


# Phishstats API Search
def PhishstatsOSINT(phishstats_file, ConfPHISHSTATS_url, ConfPHISHSTATS_keep, PROXY, SearchString, LOG):
    global HTMLText
    try:
        proxies = {'http': PROXY, 'https': PROXY}
        try:
            # If more than one search word
            if ',' in SearchString:
                SearchString_list = [SearchString.strip(' ') for SearchString in SearchString.split(',')]
                print(SearchString_list)
            else:
                SearchString_list = [SearchString]
        except:
            err = sys.exc_info()
            LOG.error("SearchString error " + str(err))

        # Using CloudFlare Scraper
        scraper = cfscrape.create_scraper()
        r = scraper.get(ConfPHISHSTATS_url + "(title,like,~" + SearchString + "~)", timeout=(10, 20))

        # download Phishstats' JSON file
        with open(phishstats_file, "wb") as file:
            file.write(r.content)
            LOG.info("Phishstats\' file retrieved. Proceeding to extraction...")

    except requests.exceptions.ConnectTimeout as e:
        LOG.error("Error while connecting to Phishstats: {}".format(e))
        pass
    except Exception as e:
        LOG.error("Phishstats connection error: {}".format(e))
        sys.exit(0)
        pass


# Parse Phishstats result
def PhishstatsExtractor(phishstats_file, SearchString, LOG, SQL, TABLEname, PROXY, UAFILE):
    UAG = UAgent()

    try:
        file = json.loads(open(phishstats_file).read())
        # Search in Phishstats JSON file
        for entry in file:
            print(entry['url'])
            bla = entry['url']
            SiteURLSQL(phishstats_file, bla, LOG, SQL, TABLEname, PROXY, UAFILE, UAG)

    except TypeError:
        pass

    except Exception as e:
        LOG.error("Phishstats JSON parser Error: {}".format(e))


# Delete Phishstats downloaded file, or not
def DeletePhishstatsFile(phishstats_file, LOG):
    # Delete phishstats_file
    try:
        os.remove(phishstats_file)
        LOG.info("File " + phishstats_file + " deleted.")
    except:
        LOG.error("Can't delete " + phishstats_file + " !!!")
        pass
