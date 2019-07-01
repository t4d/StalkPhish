#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of StalkPhish - see https://github.com/t4d/StalkPhish

import requests


def HTTPCode(url, user_agent):
    proxies = None
    try:
        r = requests.get(url=url, proxies=proxies, headers=user_agent, allow_redirects=True, timeout=(5, 12))
        lastHTTPcode = str(r.status_code)
        print(lastHTTPcode)

    except ValueError:
        r = requests.get(url=url, proxies=proxies, allow_redirects=True, timeout=(5, 12), headers={'User-agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_3 like Mac OS X) AppleWebKit/603.3.8 (KHTML, like Gecko) Version/10.0 Mobile/14G60 Safari/602.1'})
        lastHTTPcode = str(r.status_code)
        print(lastHTTPcode)

    except requests.exceptions.ConnectionError:
        print('Connection Error.')
