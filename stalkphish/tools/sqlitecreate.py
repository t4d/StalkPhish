#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys


class SqliteCreate:
    '''Sqlite3 DB creation'''
    def __init__(self, DBfile):
        try:
            file = open(DBfile, 'w+')
        except:
            err = sys.exc_info()
            print(err)
