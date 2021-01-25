#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of StalkPhish - see https://github.com/t4d/StalkPhish

import sqlite3
import sys


class SqliteCmd(object):
    '''Sqlite3 DB commands'''
    def __init__(self, DBfile):
        self.conn = sqlite3.connect(DBfile)
        self.cur = self.conn.cursor()

    # Main DB operations
    def SQLiteCreateTable(self, TABLEname):
        '''Creating main Table if not exist'''
        self.cur.execute('CREATE TABLE IF NOT EXISTS ' + TABLEname + ' (siteURL TEXT NOT NULL PRIMARY KEY, siteDomain TEXT, IPaddress TEXT, SRClink TEXT, time TEXT, lastHTTPcode TEXT, StillInvestig TEXT, StillTryDownload TEXT, page_hash TEXT, ASN TEXT)')

    def SQLiteInsertPK(self, TABLEname, siteURL, siteDomain, IPaddress, SRClink, now, lastHTTPcode, ASN):
        '''Insert new Phishing Kit infos'''
        self.cur.execute('INSERT OR IGNORE INTO ' + TABLEname + ' VALUES (?,?,?,?,?,?,?,?,?,?);', (siteURL, siteDomain, IPaddress, SRClink, now, lastHTTPcode, '', '', '', ASN))
        self.conn.commit()

    def SQLiteInsertStillInvestig(self, TABLEname, siteURL):
        '''Insert StillInvestig changes'''
        try:
            self.cur.execute('UPDATE ' + TABLEname + ' SET StillInvestig =\'Y\' WHERE siteURL=?;', (siteURL,))
            self.conn.commit()
        except:
            err = sys.exc_info()
            print("[!!!] SQLiteInsertStillInvestig Error: " + str(err))
            # print("[!!!] SQLiteInsertInvestigPK Error: " + str(err))

    def SQLiteInsertStillTryDownload(self, TABLEname, siteURL):
        '''Insert StillTryDownload changes'''
        try:
            self.cur.execute('UPDATE ' + TABLEname + ' SET StillTryDownload =\'Y\' WHERE siteURL LIKE \'' + siteURL + '%\';')
            self.conn.commit()
        except:
            err = sys.exc_info()
            print("[!!!] SQLiteInsertStillTryDownload Error: " + str(err))

    def SQLiteInsertPageHash(self, TABLEname, siteURL, PageHash):
        '''Insert StillTryDownload changes'''
        try:
            self.cur.execute('UPDATE ' + TABLEname + ' SET page_hash=' + "\"" + PageHash + "\"" + ' WHERE siteURL LIKE ' + "\"" + siteURL + "%\"" + ';')
            self.conn.commit()
        except:
            err = sys.exc_info()
            print("[!!!] SQLiteInsertPageHash Error: " + str(err))

    def SQLiteVerifyEntry(self, TABLEname, siteURL):
        '''Verify if entry still exist'''
        res = self.cur.execute('SELECT EXISTS (SELECT 1 FROM ' + TABLEname + ' WHERE siteURL LIKE ' + "\"" + siteURL + "%\"" + ' LIMIT 1);')
        fres = res.fetchone()[0]
        # 0ô
        if fres != 0:
            return 1
        else:
            return 0

    # Investigation DB operations
    def SQLiteInvestigCreateTable(self, InvTABLEname):
        '''Creating Investigation Table if not exist'''
        self.cur.execute('CREATE TABLE IF NOT EXISTS ' + InvTABLEname + ' (siteURL TEXT NOT NULL PRIMARY KEY, siteDomain TEXT, IPaddress TEXT, ZipFileName TEXT, ZipFileHash TEXT, FirstSeentime TEXT, FirstSeenCode TEXT, LastSeentime TEXT, LastSeenCode TEXT, PageTitle TEXT, extracted_emails TEXT)')

    def SQLiteInvestigInsert(self, InvTABLEname, siteURL, siteDomain, IPaddress, now, lastHTTPcode):
        '''Insert new URL info into Investigation table'''
        try:
            self.cur.execute('INSERT OR IGNORE INTO ' + InvTABLEname + '(siteURL, siteDomain, IPaddress, FirstSeentime, FirstSeenCode) VALUES (?,?,?,?,?);', (siteURL, siteDomain, IPaddress, now, lastHTTPcode))
            self.conn.commit()
        except:
            err = sys.exc_info()
            print("[!!!] SQLiteInvestigInsert Error: " + str(err))

    def SQLiteInvestigUpdatePK(self, InvTABLEname, siteURL, ZipFileName, ZipFileHash, now, lastHTTPcode):
        '''Update new Phishing Kit Investigation infos'''
        try:
            self.cur.execute('UPDATE ' + InvTABLEname + ' SET ZipFileName=?, ZipFileHash=?, LastSeentime=?, LastSeenCode=?  where siteURL=?;', (ZipFileName, ZipFileHash, now, lastHTTPcode, siteURL))
            self.conn.commit()
        except:
            err = sys.exc_info()
            print("[!!!] SQLiteInvestigUpdatePK Error: " + str(err))

    def SQLiteInvestigUpdateCode(self, InvTABLEname, siteURL, now, lastHTTPcode):
        '''Update new HTTP code infos in Investigation table'''
        self.cur.execute('UPDATE ' + InvTABLEname + ' SET LastSeentime=?, LastSeenCode=?  where siteURL=?;', (now, lastHTTPcode, siteURL))
        self.conn.commit()

    def SQLiteInvestigUpdateTitle(self, InvTABLEname, siteURL, PageTitle):
        '''Add Page title in Investigation table'''
        self.cur.execute('UPDATE ' + InvTABLEname + ' SET  PageTitle=? where siteURL=?;', (PageTitle, siteURL))
        self.conn.commit()

    def SQLiteInvestigState(self, TABLEname, siteURL):
        '''Update new HTTP code infos in StillInvestig column'''
        self.cur.execute('UPDATE ' + TABLEname + ' SET StillInvestig=\'Y\'  where siteURL=?;', (siteURL,))
        self.conn.commit()

    def SQLiteDownloadedState(self, TABLEname, siteURL):
        '''Update new HTTP code infos in StillTryDownload column'''
        self.cur.execute('UPDATE ' + TABLEname + ' SET StillTryDownload=\'Y\'  where siteURL=?;', (siteURL,))
        self.conn.commit()

    def SQLiteInvestigInsertEmail(self, InvTABLEname, extracted_emails, ZipFileName):
        self.cur.execute('UPDATE ' + InvTABLEname + ' SET  extracted_emails=? where ZipFileName=?;', (extracted_emails, ZipFileName))
        self.conn.commit()

    def SQLiteInvestigVerifyEntry(self, InvTABLEname, siteDomain, IPaddress):
        '''Verify if entry still exist'''
        res = self.cur.execute('SELECT EXISTS (SELECT 1 FROM ' + InvTABLEname + ' WHERE (siteDomain=? AND IPaddress=?)) LIMIT 1;', (siteDomain, IPaddress))
        fres = res.fetchone()[0]
        # 0ô
        if fres != 0:
            return 1
        else:
            return 0

    # Select requests
    def SQLiteSearch200(self, TABLEname):
        '''Searching for UP phishing kit'''
        self.cur.execute('SELECT siteURL, siteDomain, IPaddress FROM ' + TABLEname + ' WHERE lastHTTPcode IS 200;')
        return self.cur.fetchall()

    def SQLiteSearchNotInvestig(self, TABLEname):
        '''Searching for Still not Investigate URL'''
        self.cur.execute('SELECT siteURL, siteDomain, IPaddress FROM ' + TABLEname + ' WHERE StillInvestig IS NOT \'Y\';')
        return self.cur.fetchall()

    def SQLiteSearchNotDownloaded(self, TABLEname):
        '''Searching for Still not Downloaded PK'''
        self.cur.execute('SELECT siteURL, siteDomain, IPaddress FROM ' + TABLEname + ' WHERE StillTryDownload IS NOT \'Y\';')
        return self.cur.fetchall()

    def SQLiteSearchDateString(self, TABLEname, DateString):
        '''Searching for piece of date string'''
        self.cur.execute('SELECT siteURL, siteDomain, IPaddress FROM ' + TABLEname + ' WHERE time like \'%' + DateString + '%\';')
        return self.cur.fetchall()

    def SQLiteSearchInvestigSiteURL(self, InvTABLEname, ZipFileName):
        '''Searching for SiteURL of downloaded phishing kit'''
        self.cur.execute('SELECT siteURL FROM ' + InvTABLEname + ' WHERE ZipFileName IS ?;', (ZipFileName,))
        return self.cur.fetchall()

    def __del__(self):
        try:
            self.cur.close()
            self.conn.close()
        except:
            pass

    def SQLiteClose(self):
        self.__del__()
