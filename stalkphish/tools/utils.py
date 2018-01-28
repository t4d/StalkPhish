#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of StalkPhish - see https://github.com/t4d/StalkPhish

import os
import sys
import datetime
import hashlib
import random

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
			print("[!!!] VerifyPath class Error: "+str(err))

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