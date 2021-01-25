#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#   StalkPhish - The Phishing kits stalker
#   Copyright (C) 2018-2020 Thomas "tAd" Damonneville
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU Affero General Public License as
#   published by the Free Software Foundation, either version 3 of the
#   License, or (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU Affero General Public License for more details.
#
#   You should have received a copy of the GNU Affero General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import glob
import time
import getopt
import socket
from tools.utils import VerifyPath
from tools.utils import NetInfo
from tools.sqlite import SqliteCmd
from tools.addurl import AddUniqueURL
from tools.logging import Logger
from tools.confparser import ConfParser
VERSION = "0.9.8-3"


# Graceful banner  :)
def banner():
    banner = '''
  _____ _        _ _    _____  _     _     _
 / ____| |      | | |  |  __ \| |   (_)   | |    
| (___ | |_ __ _| | | _| |__) | |__  _ ___| |__  
 \___ \| __/ _` | | |/ /  ___/| '_ \| / __| '_ \ 
 ____) | || (_| | |   <| |    | | | | \__ \ | | |
|_____/ \__\__,_|_|_|\__\|    |_| |_|_|___/_| |_|
'''
    print(banner)
    print("-= StalkPhish - The Phishing Kit stalker - v" + VERSION + " =-\n")


# Usage
def usage():
    usage = """
    -h --help       Prints this help
    -c --config     Configuration file to use (mandatory)
    -G --get        Try to download zip file containing phishing kit sources (long and noisy)
    -N --nosint     Don't use OSINT databases
    -u --url        Add only one URL
    -s --search     Search for a specific string on OSINT modules
    """
    print(usage)
    sys.exit(0)


# Tool options
def args_parse():
    global ConfFile
    global DLPhishingKit
    global OSINTsources
    global UniqueURL
    global URLadd
    global SearchUString
    confound = "NO"
    DLPhishingKit = "NO"
    OSINTsources = "YES"
    UniqueURL = "NO"
    URLadd = ""
    SearchUString = ""

    if not len(sys.argv[1:]):
        usage()
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hNGc:u:s:", ["help", "nosint", "get", "conf=", "url=", "search="])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-c", "--config"):
            if os.path.isfile(a):
                ConfFile = a
                confound = "YES"
            else:
                print("  ERROR - Can't find configuration file.")
                usage()
        elif confound == "NO":
            print("  Error - Configuration file is mandatory.")
            usage()

        elif o in ("-N", "--nosint"):
            OSINTsources = "NO"
        elif o in ("-G", "--get"):
            DLPhishingKit = "YES"
        elif o in ("-u", "--url"):
            UniqueURL = "YES"
            URLadd = a
        elif o in ("-s", "--search"):
            SearchUString = a
        else:
            assert False, "Unhandled Option"
    return


# Modules initialization
def LaunchModules(SearchString):
    LOG.info("Proceeding to OSINT modules launch")
    try:
        # If more than one search word
        if ',' in SearchString:
            SearchString_list = [SearchString.strip(' ') for SearchString in SearchString.split(',')]
        else:
            SearchString_list = [SearchString]
    except:
        err = sys.exc_info()
        LOG.error("SearchString error " + str(err))

    ###################
    # URLScan module #
    ###################
    ModuleUrlscan = CONF.URLSCAN_active
    if ModuleUrlscan is True:
        from modules.urlscan import UrlscanOSINT, UrlscanExtractor
        ConfURLSCAN_url = CONF.URLSCAN_url
        ConfURLSCAN_apikey = CONF.URLSCAN_apikey

        for SearchString in SearchString_list:
            UrlscanOSINT(ConfURLSCAN_apikey, ConfURLSCAN_url, PROXY, SearchString, LOG)
            UrlscanExtractor(LOG, SQL, TABLEname, PROXY, UAFILE)
    else:
        pass

    ###################
    # URLQUERY module #
    ###################
    ModuleUrlquery = CONF.URLQUERY_active
    if ModuleUrlquery is True:
        from modules.urlquery import UrlqueryOSINT, UrlqueryExtractor
        ConfURLQUERY_url = CONF.URLQUERY_url

        for SearchString in SearchString_list:
            UrlqueryOSINT(ConfURLQUERY_url, PROXY, SearchString, LOG)
            UrlqueryExtractor(SearchString, LOG, SQL, TABLEname, PROXY, UAFILE)
    else:
        pass

    ####################
    # PHISHTANK module #
    ####################
    ModulePhishtank = CONF.PHISHTANK_active
    if ModulePhishtank is True:
        from modules.phishtank import PhishtankOSINT, PhishtankExtractor, DeletePhishtankFile
        ConfPHISHTANK_url = CONF.PHISHTANK_url
        ConfPHISHTANK_keep = CONF.PHISHTANK_keep
        ConfPHISHTANK_apikey = CONF.PHISHTANK_apikey

        try:
            if ConfPHISHTANK_apikey is not None:
                ConfPHISHTANK_url = "https://data.phishtank.com/data/{}/online-valid.json".format(ConfPHISHTANK_apikey)
                pass
        except:
            LOG.error("There's a problem with API key. Trying without...")
            pass

        try:
            # Get PHISHTANK free feed (if older than 1 hour)
            phishtank_file = ""
            filelist = glob.glob(SrcDir + "phishtank-feed-*.json")
            if filelist:
                last_phishtank_file = max(filelist, key=os.path.getctime)
                if os.stat(last_phishtank_file).st_mtime < time.time() - 7200:
                    # file older than 2 hours, download a new one
                    phishtank_file = SrcDir + "phishtank-feed-" + time.strftime("%Y%m%d-%H%M") + ".json"
                    PhishtankOSINT(phishtank_file, ConfPHISHTANK_url, ConfPHISHTANK_keep, SrcDir, PROXY, LOG)
                else:
                    LOG.info("Phishtank\'s file still exist (<2h). Proceeding to extraction...")
                    phishtank_file = last_phishtank_file
            else:
                phishtank_file = SrcDir + "phishtank-feed-" + time.strftime("%Y%m%d-%H%M") + ".json"
                PhishtankOSINT(phishtank_file, ConfPHISHTANK_url, ConfPHISHTANK_keep, SrcDir, PROXY, LOG)

            for SearchString in SearchString_list:
                # Search into file
                LOG.info("Searching for \'" + SearchString + "\'...")
                PhishtankExtractor(phishtank_file, SearchString, LOG, SQL, TABLEname, PROXY, UAFILE)

            # Proceed to file delete if don't want to keep it
            if ConfPHISHTANK_keep is not True:
                DeletePhishtankFile(phishtank_file, LOG)
            else:
                pass
        # if sys.exit() from Phishtank module
        except SystemExit:
            pass
        except:
            err = sys.exc_info()
            LOG.error("Phishtank module error: " + str(err))

    else:
        pass

    ####################
    # OPENPHISH module #
    ####################
    ModuleOpenPhish = CONF.OPENPHISH_active
    if ModuleOpenPhish is True:
        from modules.openphish import OpenphishOSINT, OpenphishExtractor, DeleteOpenphishFile
        ConfOPENPHISH_url = CONF.OPENPHISH_url
        ConfOPENPHISH_keep = CONF.OPENPHISH_keep

        try:
            # Get OPENPHISH free feed (if older than 1 hour)
            openphish_file = ""
            filelist = glob.glob(SrcDir + "openphish-feed-*.txt")
            if filelist:
                last_openphish_file = max(filelist, key=os.path.getctime)
                if os.stat(last_openphish_file).st_mtime < time.time() - 7200:
                    # file older than 2 hours, download a new one
                    openphish_file = SrcDir + "openphish-feed-" + time.strftime("%Y%m%d-%H%M") + ".txt"
                    OpenphishOSINT(openphish_file, ConfOPENPHISH_url, ConfOPENPHISH_keep, SrcDir, PROXY, LOG)
                else:
                    LOG.info("Openphish\'s file still exist (<2h). Proceeding to extraction...")
                    openphish_file = last_openphish_file
            else:
                openphish_file = SrcDir + "openphish-feed-" + time.strftime("%Y%m%d-%H%M") + ".txt"
                OpenphishOSINT(openphish_file, ConfOPENPHISH_url, ConfOPENPHISH_keep, SrcDir, PROXY, LOG)

            for SearchString in SearchString_list:
                # Search into file
                LOG.info("Searching for \'" + SearchString + "\'...")
                OpenphishExtractor(openphish_file, SearchString, LOG, SQL, TABLEname, PROXY, UAFILE)

            # Proceed to file delete if don't want to keep it
            if ConfOPENPHISH_keep is not True:
                DeleteOpenphishFile(openphish_file, LOG)
            else:
                pass

        except:
            err = sys.exc_info()
            LOG.error("Openphish module error: " + str(err))
    else:
        pass

    ####################
    # Phihstats module #
    ####################
    ModulePhishstats = CONF.PHISHSTATS_active
    if ModulePhishstats is True:
        from modules.phishstats import PhishstatsOSINT, PhishstatsExtractor, DeletePhishstatsFile
        ConfPHISHSTATS_url = CONF.PHISHSTATS_url
        ConfPHISHSTATS_keep = CONF.PHISHSTATS_keep

        try:
            # Get PHISHSTATS free feed (if older than 2 hour)
            phishstats_file = ""
            filelist = glob.glob(SrcDir + "phishstats-feed-*.json")
            if filelist:
                last_phishstats_file = max(filelist, key=os.path.getctime)
                if os.stat(last_phishstats_file).st_mtime < time.time() - 7200:
                    # file older than 2 hours, download a new one
                    phishstats_file = SrcDir + "phishstats-feed-" + time.strftime("%Y%m%d-%H%M") + ".json"
                    PhishstatsOSINT(phishstats_file, ConfPHISHSTATS_url, ConfPHISHSTATS_keep, PROXY, SearchString, LOG)
                else:
                    LOG.info("Phishstats\'s file still exist (<2h). Proceeding to extraction...")
                    phishstats_file = last_phishstats_file
            else:
                phishstats_file = SrcDir + "phishstats-feed-" + time.strftime("%Y%m%d-%H%M") + ".json"
                PhishstatsOSINT(phishstats_file, ConfPHISHSTATS_url, ConfPHISHSTATS_keep, PROXY, SearchString, LOG)

            for SearchString in SearchString_list:
                # Search into file
                LOG.info("Searching for \'" + SearchString + "\'...")
                PhishstatsExtractor(phishstats_file, SearchString, LOG, SQL, TABLEname, PROXY, UAFILE)

            # Proceed to file delete if don't want to keep it
            if ConfPHISHSTATS_keep is not True:
                DeletePhishstatsFile(phishstats_file, LOG)
            else:
                pass
        # if sys.exit() from Phishtank module
        except SystemExit:
            pass
        except:
            err = sys.exc_info()
            LOG.error("Phishstats module error: " + str(err))
    else:
        pass

    ############################
    # Phishing.Database module #
    ############################
    ModulePhishingDB = CONF.PHISHINGDB_active
    if ModulePhishingDB is True:
        from modules.phishingdb import PhishingDBOSINT, PhishingDBExtractor, DeletePhishingDBFile
        ConfPHISHINGDB_url = CONF.PHISHINGDB_url
        ConfPHISHINGDB_keep = CONF.PHISHINGDB_keep

        try:
            # Get Phishing.Database free feed (if older than 1 hour)
            phishingdb_file = ""
            filelist = glob.glob(SrcDir + "phishingdb-feed-*.txt")
            if filelist:
                last_phishingdb_file = max(filelist, key=os.path.getctime)
                if os.stat(last_phishingdb_file).st_mtime < time.time() - 7200:
                    # file older than 2 hours, download a new one
                    phishingdb_file = SrcDir + "phishingdb-feed-" + time.strftime("%Y%m%d-%H%M") + ".txt"
                    PhishingDBOSINT(phishingdb_file, ConfPHISHINGDB_url, ConfPHISHINGDB_keep, SrcDir, PROXY, LOG)
                else:
                    LOG.info("Phishing.Database\'s file still exist (<2h). Proceeding to extraction...")
                    phishingdb_file = last_phishingdb_file
            else:
                phishingdb_file = SrcDir + "phishingdb-feed-" + time.strftime("%Y%m%d-%H%M") + ".txt"
                PhishingDBOSINT(phishingdb_file, ConfPHISHINGDB_url, ConfPHISHINGDB_keep, SrcDir, PROXY, LOG)

            for SearchString in SearchString_list:
                # Search into file
                LOG.info("Searching for \'" + SearchString + "\'...")
                PhishingDBExtractor(phishingdb_file, SearchString, LOG, SQL, TABLEname, PROXY, UAFILE)

            # Proceed to file delete if don't want to keep it
            if ConfPHISHINGDB_keep is not True:
                DeletePhishingDBFile(phishingdb_file, LOG)
            else:
                pass

        except:
            err = sys.exc_info()
            LOG.error("Openphish module error: " + str(err))
    else:
        pass

# Try to download Phshing kit sources
def TryDLPK(TABLEname, InvTABLEname, DLDir, SQL, PROXY, LOG, UAFILE):
    from tools.download import TryPKDownload
    # Search in main Table for StillTryDownload column
    rows = SQL.SQLiteSearchNotDownloaded(TABLEname)
    try:
        for row in rows:
            siteDomain = row[1]
            IPaddress = row[2]
            if IPaddress:
                rASN = NetInfo()
                if rASN.GetASN(IPaddress):
                    ASN = rASN.GetASN(IPaddress).strip('\"')
                else:
                    ASN = None
            else:
                ASN = None
            if row[0].startswith('https'):
                siteURL = row[0]
            if row[0].startswith('http'):
                siteURL = str(row[0])
            else:
                siteURL = 'http://' + row[0]
            TryPKDownload(siteURL, siteDomain, IPaddress, TABLEname, InvTABLEname, DLDir, SQL, PROXY, LOG, UAFILE, ASN)
    except:
        err = sys.exc_info()
        LOG.error("TryDLPK module error: " + str(err))


# Config file read
def ConfAnalysis(ConfFile):
    global UA
    global UAFILE
    global CONF
    global DBfile
    global DBDir
    global SrcDir
    global DLDir
    global PROXY
    global TABLEname
    global InvTABLEname
    global SearchString
    global LogConf
    global LogDir
    global LogFile
    global LOG

    try:
        CONF = ConfParser(ConfFile)
        P = VerifyPath()

        # Database stuff
        DBfile = CONF.DBfile
        TABLEname = CONF.TABLEname
        InvTABLEname = CONF.InvestigTABLEname

        # Path stuff
        SrcDir = CONF.SrcDir
        P.VerifyOrCreate(SrcDir)
        DBDir = CONF.DatabaseDir
        P.VerifyOrCreate(DBDir)
        DLDir = CONF.DLDir
        P.VerifyOrCreate(DLDir)

        # Connection stuff
        PROXY = CONF.http_proxy
        UA = CONF.http_UA
        UAFILE = CONF.UAfile

        # Search stuff
        if SearchUString:
            SearchString = SearchUString
        else:
            SearchString = CONF.SearchString

        # Logging stuff
        LogConf = CONF.LogConf
        LogDir = CONF.LogDir
        P.VerifyOrCreate(LogDir)
        LogFile = CONF.LogFile
        llog = LogDir + LogFile
        LOG = Logger(llog)

    except:
        err = sys.exc_info()
        LOG.error("ConfAnalysis error " + str(err))


# Main
def main():
    global SQL
    try:
        # Config
        ConfAnalysis(ConfFile)

        # Output options
        P = VerifyPath()
        LOG.info("Configuration file to use: " + ConfFile)
        LOG.info("Database: " + DBfile)
        SQL = SqliteCmd(DBfile)
        LOG.info("Main table: " + TABLEname)
        SQL.SQLiteCreateTable(TABLEname)
        LOG.info("Investigation table: " + InvTABLEname)
        SQL.SQLiteInvestigCreateTable(InvTABLEname)
        LOG.info("Files directory: " + SrcDir)
        LOG.info("Download directory: " + DLDir)
        LOG.info("Declared Proxy: " + str(PROXY) + "\n")

        # Test proxy connection
        if PROXY:
            proxystring = PROXY.split('//')[1]
            proxyipadd = proxystring.split(':')[0]
            proxyport = proxystring.split(':')[1]
            s = socket.socket()
            try:
                s.connect((proxyipadd, int(proxyport)))
            except:
                LOG.error("Proxy connection error, exiting!")
                os._exit(1)
        else:
            pass

        # Only add URL into Database
        if UniqueURL == "YES":
            LOG.info("Add URL into database: {}".format(URLadd))
            AddUniqueURL(URLadd, LOG, SQL, TABLEname, PROXY, UAFILE)
            sys.stdout.flush()
            os._exit(0)
        else:
            pass

        # Modules launch
        if OSINTsources == "YES":
            LaunchModules(SearchString)
        else:
            pass

        # Phishing Kit download launch if activated
        if DLPhishingKit == "YES":
            LOG.info("Starting trying to download phishing kits sources...")
            TryDLPK(TABLEname, InvTABLEname, DLDir, SQL, PROXY, LOG, UAFILE)
        else:
            pass

    except KeyboardInterrupt:
        LOG.info("Shutdown requested...exiting")
        os._exit(0)

    except:
        err = sys.exc_info()
        LOG.error("Main error " + str(err))


# Start
if __name__ == '__main__':
    banner()
    args_parse()
    main()
