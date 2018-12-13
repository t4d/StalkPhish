#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of StalkPhish - see https://github.com/t4d/StalkPhish

import sys
import logging
from logging.handlers import RotatingFileHandler


def Logger(LogFile):
    try:
        # Create the Logger
        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)

        # stdout logging handler
        stdout_logger_handler = logging.StreamHandler()
        stdout_logger_handler.setLevel(logging.INFO)

        # Handler for file logging (10Mb rotating logs x10)
        file_logger_handler = logging.handlers.RotatingFileHandler(LogFile, mode='a', maxBytes=10000000, backupCount=10)
        file_logger_handler.setLevel(logging.DEBUG)

        # Create a Formatter for formatting the log messages
        logger_formatter = logging.Formatter('%(asctime)s - %(filename)s - %(levelname)s - %(message)s')

        # Add the Formatter to the Handlers
        file_logger_handler.setFormatter(logger_formatter)
        stdout_logger_handler.setFormatter(logger_formatter)

        # Add handlers to the Logger
        logger.addHandler(file_logger_handler)
        logger.addHandler(stdout_logger_handler)

        return logger

    except:
        err = sys.exc_info()
        print("[!!!] Logging Error: " + str(err))
