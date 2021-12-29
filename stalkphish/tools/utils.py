#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of StalkPhish - see https://github.com/t4d/StalkPhish

import os
import re
import sys
import zipfile
import datetime
import hashlib
import random
from ipwhois.net import Net
from ipwhois.asn import IPASN
import json


class TimestampNow:
    '''Generate Timestamp'''
    def Timestamp(self):
        now = datetime.datetime.now().strftime("%c")
        return now


class VerifyPath:
    '''Verify or create path if not exist'''
    def VerifyOrCreate(self, path):
        try:
            os.makedirs(path, mode=0o777, exist_ok=True)
        except FileExistsError:
            pass
        except:
            err = sys.exc_info()
            print("[!!!] VerifyPath class Error: " + str(err))


class SHA256:
    '''Generate sha256 hash of a file'''
    def hashFile(self, filename, block_size=65536):
        h = hashlib.sha256()
        try:
            with open(filename, 'rb') as f:
                buf = f.read(block_size)
                while len(buf) > 0:
                    h.update(buf)
                    buf = f.read(block_size)
                    filehash = h.hexdigest()
            return filehash
        except:
            err = sys.exc_info()
            print("[!!!] Error in hashFile Class: " + str(err))


class UAgent:
    '''Choose a random user-agent from a file'''
    def ChooseUA(self, UAfile):
        try:
            with open(UAfile, 'rb') as f:
                UA = random.choice(list(f)).strip().decode("utf-8")
                return UA
        except:
            err = sys.exc_info()
            print("[!!!] Problem with UserAgent Class: " + str(err))


class NetInfo:
    '''Retrieve network informations'''
    def GetASN(self, IPaddress):
        '''Retrieve AS Number of an IP address'''
        try:
            if IPaddress:
                net = Net(IPaddress)
                obj = IPASN(net)
                res = obj.lookup()
                IPasn = json.dumps(res["asn"])
            else:
                IPasn = None
            return IPasn
        except:
            err = sys.exc_info()
            print("[!!!] Problem with NetInfo Class: " + str(err))


class ZipSearch:
    '''Search for e-mail addresses into Zip file'''
    def PKzipSearch(self, InvTABLEname, SQL, LOG, DLDir, savefile):
        try:
            # print(zipfile.getinfo(savefile))
            if zipfile.is_zipfile(savefile):
                file = zipfile.ZipFile(savefile, "r")
                extracted_emails = []
                for name in file.namelist():
                    if re.findall("php|ini$", name):
                        scam_email2 = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', str(file.read(name)))
                        for mailadd in scam_email2:
                            if mailadd not in extracted_emails:
                                extracted_emails.append(mailadd)
                # Extracted scammers email
                if any(map(len, extracted_emails)):
                    return [extracted_emails]
                else:
                    LOG.info("No emails in this kit")
                    pass
            else:
                LOG.info("{} is not a zip file...".format(savefile))
        except Exception as e:
            print("[!!!] Problem with PKzipSearch Class: " + str(e))
