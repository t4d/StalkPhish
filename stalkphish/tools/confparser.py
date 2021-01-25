#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of StalkPhish - see https://github.com/t4d/StalkPhish

import sys
import configparser


class ConfParser:
    '''Configuration file parser'''
    def __init__(self, Confile=None):
        try:
            self.config = configparser.ConfigParser()

            with open(Confile, 'r', encoding='utf-8') as f:
                self.config.readfp(f)

                # search string(s) (comma separated)
                self.SearchString = self.config['SEARCH']['search']

                # Databases
                self.DatabaseDir = self.config['DATABASE']['Databases_files']
                self.DBfile = self.config['DATABASE']['sqliteDB_filename']
                self.TABLEname = self.config['DATABASE']['sqliteDB_tablename']
                self.InvestigTABLEname = self.config['DATABASE']['sqliteDB_Investig_tablename']

                # Paths
                # Logging
                self.LogConf = self.config['PATHS']['log_conf']
                self.LogDir = self.config['PATHS']['log_dir']
                self.LogFile = self.config['PATHS']['log_file']

                self.DLDir = self.config['PATHS']['Kits_download_Dir']
                self.SrcDir = self.config['PATHS']['Ext_src_Files']

                # Proxy
                try:
                    self.http_proxy = self.config['CONNECT']['http_proxy']
                except:
                    self.http_proxy = None

                self.http_UA = self.config['CONNECT']['http_UA']
                self.UAfile = self.config['CONNECT']['UAfile']

                # Modules
                self.URLSCAN_active = self.config['URLSCAN'].getboolean('activate')
                self.URLSCAN_url = self.config['URLSCAN']['API_url']
                try:
                    self.URLSCAN_apikey = self.config['URLSCAN']['API_key']
                except:
                    self.URLSCAN_apikey = None

                self.URLQUERY_active = self.config['URLQUERY'].getboolean('activate')
                self.URLQUERY_url = self.config['URLQUERY']['OSINT_url']

                self.PHISHTANK_active = self.config['PHISHTANK'].getboolean('activate')
                self.PHISHTANK_url = self.config['PHISHTANK']['OSINT_url']
                self.PHISHTANK_keep = self.config['PHISHTANK'].getboolean('keep_files')
                try:
                    self.PHISHTANK_apikey = self.config['PHISHTANK']['API_key']
                except:
                    self.PHISHTANK_apikey = None

                self.OPENPHISH_active = self.config['OPENPHISH'].getboolean('activate')
                self.OPENPHISH_url = self.config['OPENPHISH']['OSINT_url']
                self.OPENPHISH_keep = self.config['OPENPHISH'].getboolean('keep_files')

                self.PHISHSTATS_active = self.config['PHISHSTATS'].getboolean('activate')
                self.PHISHSTATS_url = self.config['PHISHSTATS']['OSINT_url']
                self.PHISHSTATS_keep = self.config['PHISHSTATS'].getboolean('keep_files')

                self.PHISHINGDB_active = self.config['Phishing.Database'].getboolean('activate')
                self.PHISHINGDB_url = self.config['Phishing.Database']['OSINT_url']
                self.PHISHINGDB_keep = self.config['Phishing.Database'].getboolean('keep_files')

        except IOError:
            print("[!!!] Configuration file Error: " + Confile)
        except:
            err = sys.exc_info()
            print("[!!!] ConfParser Error: " + str(err))
