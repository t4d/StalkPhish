#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of StalkPhish - see https://github.com/t4d/StalkPhish

import sys
import sqlite3
from tools.confparser import ConfParser

class SqliteCreate:
	'''Sqlite3 DB creation'''
	def __init__(self, DBfile):
		try:
			file = open(DBfile, 'w+')
		except:
			err = sys.exc_info()
			print(err)