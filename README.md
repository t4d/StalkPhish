# StalkPhish
*StalkPhish - The Phishing kits stalker*

**StalkPhish** is a tool created for searching into free OSINT databases for specific phishing kits URL. More, **StalkPhish** is designed to try finding phishing kits sources. Some scammers can't or don't remove their phishing kit sources when they deploy it. You can try to find these sources to extract some useful information as: e-mail addresses where is send stolen data, some more information about scammer or phishing kit developer. From there you can extend your knowledge about the threat and organizations, and get much useful information for your investigations.

## Features
- find URL where a phishing kit is deployed (from OSINT databases)
- find if the phishing kit is still up and running
- try to download phishing kit sources
- use a hash of the phishing kit archive to identify the kit and threat
- use timestamps for history
- can use HTTP or SOCKS5 proxy (for downloading)

## OSINT modules
* [urlscan.io](https://urlscan.io/about-api/) search API
* [urlquery.net](https://urlquery.net/search) search web crawler
* [Phishtank](https://www.phishtank.com/developer_info.php) free OSINT feed
* [Openphish](https://openphish.com/phishing_feeds.html) free OSINT feed

## Requirements
* Python 3
* requests
* PySocks

## Install
Install the requirements
~~~
pip3 install -r requirements.txt
~~~

## Help
~~~
$ ./StalkPhish.py -h

  _____ _        _ _    _____  _     _     _
 / ____| |      | | |  |  __ \| |   (_)   | |    
| (___ | |_ __ _| | | _| |__) | |__  _ ___| |__  
 \___ \| __/ _` | | |/ /  ___/| '_ \| / __| '_ \ 
 ____) | || (_| | |   <| |    | | | | \__ \ | | |
|_____/ \__\__,_|_|_|\__\|    |_| |_|_|___/_| |_|

-= StalkPhish - The Phishing Kit stalker - v0.9 =-


    -h --help       Prints this help
    -c --config     Configuration file to use
    -G --get        Try to download zip file containing phishing kit sources (long and noisy)
    -N --nosint     Don't use OSINT databases
~~~

## Basic usage
~~~
$ ./StalkPhish.py -c conf/example.conf 

  _____ _        _ _    _____  _     _     _
 / ____| |      | | |  |  __ \| |   (_)   | |    
| (___ | |_ __ _| | | _| |__) | |__  _ ___| |__  
 \___ \| __/ _` | | |/ /  ___/| '_ \| / __| '_ \ 
 ____) | || (_| | |   <| |    | | | | \__ \ | | |
|_____/ \__\__,_|_|_|\__\|    |_| |_|_|___/_| |_|

-= StalkPhish - The Phishing Kit stalker - v0.9 =-

2018-01-28 14:43:31,892 - StalkPhish.py - INFO - Configuration file to use: conf/example.conf
2018-01-28 14:43:31,893 - StalkPhish.py - INFO - Database: ./db/StalkPhish.sqlite3
2018-01-28 14:43:31,894 - StalkPhish.py - INFO - Main table: StalkPhish
2018-01-28 14:43:31,903 - StalkPhish.py - INFO - Investigation table: StalkPhishInvestig
2018-01-28 14:43:31,912 - StalkPhish.py - INFO - Files directory: ./files/
2018-01-28 14:43:31,912 - StalkPhish.py - INFO - Download directory: ./dl/
2018-01-28 14:43:31,913 - StalkPhish.py - INFO - Declared Proxy: socks5://127.0.0.1:9050

2018-01-28 14:43:31,913 - StalkPhish.py - INFO - Proceeding to OSINT modules launch
2018-01-28 14:43:34,406 - urlscan.py - INFO - Searching for 'webmail'...
2018-01-28 14:43:36,394 - urlscan.py - INFO - http://finvic.org.au/wp-admin/network/webmail2/webmail/webmail.php finvic.org.au 27.121.64.82 https://urlscan.io/result/065e1ee4-9872-4c77-a12c-67b4f1c394fe Sun Jan 28 14:43:34 2018 200
2018-01-28 14:43:39,732 - urlscan.py - INFO - https://www.futures.com.tw/components/webmail/po/optus/page2.htm www.futures.com.tw 103.1.220.17 https://urlscan.io/result/fbd0e09a-635d-4a48-b023-dca4576a8031 Sun Jan 28 14:43:37 2018 500
2018-01-28 14:43:40,766 - urlscan.py - INFO - http://digidom.com/Mailbox/webmail.php digidom.com 69.89.31.123 https://urlscan.io/result/3e0624d6-279d-4d3e-81ff-ea5720608ced Sun Jan 28 14:43:39 2018 200
2018-01-28 14:43:42,212 - urlscan.py - INFO - http://finvic.org.au/wp-content/themes/webmail2/webmail/webmail.php finvic.org.au 27.121.64.82 https://urlscan.io/result/9ed37b75-2dd2-4458-832a-0d72a6bccde4 Sun Jan 28 14:43:40 2018 200
~~~

## Advanced usage (find phishing kits sources)
~~~
$ ./StalkPhish.py -c conf/example.conf -G -N

  _____ _        _ _    _____  _     _     _
 / ____| |      | | |  |  __ \| |   (_)   | |    
| (___ | |_ __ _| | | _| |__) | |__  _ ___| |__  
 \___ \| __/ _` | | |/ /  ___/| '_ \| / __| '_ \ 
 ____) | || (_| | |   <| |    | | | | \__ \ | | |
|_____/ \__\__,_|_|_|\__\|    |_| |_|_|___/_| |_|

-= StalkPhish - The Phishing Kit stalker - v0.9 =-

2018-01-28 14:45:23,072 - StalkPhish.py - INFO - Configuration file to use: conf/example.conf
2018-01-28 14:45:23,073 - StalkPhish.py - INFO - Database: ./db/StalkPhish.sqlite3
2018-01-28 14:45:23,073 - StalkPhish.py - INFO - Main table: StalkPhish
2018-01-28 14:45:23,074 - StalkPhish.py - INFO - Investigation table: StalkPhishInvestig
2018-01-28 14:45:23,074 - StalkPhish.py - INFO - Files directory: ./files/
2018-01-28 14:45:23,074 - StalkPhish.py - INFO - Download directory: ./dl/
2018-01-28 14:45:23,074 - StalkPhish.py - INFO - Declared Proxy: socks5://127.0.0.1:9050

2018-01-28 14:45:24,593 - download.py - INFO - [200] http://finvic.org.au/wp-admin/network/webmail2/webmail/webmail.php
2018-01-28 14:45:24,607 - download.py - INFO - trying http://finvic.org.au/wp-admin.zip
2018-01-28 14:45:30,318 - download.py - INFO - trying http://finvic.org.au/wp-admin/network.zip
2018-01-28 14:45:36,063 - download.py - INFO - trying http://finvic.org.au/wp-admin/network/webmail2.zip
2018-01-28 14:45:37,333 - download.py - INFO - [DL ] Found archive, downloaded it as: ./dl/http__finvic.org.au_wp-admin_network_webmail2.zip
2018-01-28 14:45:37,341 - download.py - INFO - trying http://finvic.org.au/wp-admin/network/webmail2/webmail.zip
2018-01-28 14:45:42,647 - download.py - INFO - trying http://finvic.org.au/wp-admin/network/webmail2/webmail/webmail.php.zip
2018-01-28 14:45:51,024 - download.py - INFO - [500] https://www.futures.com.tw/components/webmail/po/optus/page2.htm
2018-01-28 14:45:51,819 - download.py - INFO - [200] http://digidom.com/Mailbox/webmail.php
2018-01-28 14:45:51,832 - download.py - INFO - trying http://digidom.com/Mailbox.zip
2018-01-28 14:45:52,744 - download.py - INFO - trying http://digidom.com/Mailbox/webmail.php.zip
2018-01-28 14:45:55,071 - download.py - INFO - [200] http://finvic.org.au/wp-content/themes/webmail2/webmail/webmail.php
2018-01-28 14:45:55,079 - download.py - INFO - trying http://finvic.org.au/wp-content.zip
~~~

## SQLite3 database schema
~~~
$ sqlite3 ./db/StalkPhish.sqlite3 .schema
CREATE TABLE StalkPhish (siteURL TEXT NOT NULL PRIMARY KEY, siteDomain TEXT, IPaddress TEXT, SRClink TEXT, time TEXT, lastHTTPcode TEXT, StillInvestig TEXT, StillTryDownload TEXT);
CREATE TABLE StalkPhishInvestig (siteURL TEXT NOT NULL PRIMARY KEY, siteDomain TEXT, IPaddress TEXT, ZipFileName TEXT, ZipFileHash TEXT, FirstSeentime TEXT, FirstSeenCode TEXT, LastSeentime TEXT, LastSeenCode TEXT, PageTitle TEXT);
~~~

## SQLite3 'main' table sample example
~~~
$ sqlite3 ./db/StalkPhish.sqlite3 'select * from StalkPhish'
http://finvic.org.au/wp-admin/network/webmail2/webmail/webmail.php|finvic.org.au|27.121.64.82|https://urlscan.io/result/065e1ee4-9872-4c77-a12c-67b4f1c394fe|Sun Jan 28 14:43:34 2018|200||Y
https://www.futures.com.tw/components/webmail/po/optus/page2.htm|www.futures.com.tw|103.1.220.17|https://urlscan.io/result/fbd0e09a-635d-4a48-b023-dca4576a8031|Sun Jan 28 14:43:37 2018|500||
http://digidom.com/Mailbox/webmail.php|digidom.com|69.89.31.123|https://urlscan.io/result/3e0624d6-279d-4d3e-81ff-ea5720608ced|Sun Jan 28 14:43:39 2018|200||Y
http://finvic.org.au/wp-content/themes/webmail2/webmail/webmail.php|finvic.org.au|27.121.64.82|https://urlscan.io/result/9ed37b75-2dd2-4458-832a-0d72a6bccde4|Sun Jan 28 14:43:40 2018|200||Y
~~~

## SQLite3 'investigation' table sample example
~~~
$ sqlite3 ./db/StalkPhish.sqlite3 'select * from StalkPhishInvestig'
http://finvic.org.au/wp-admin/network/webmail2/webmail/webmail.php|finvic.org.au|27.121.64.82|http__finvic.org.au_wp-admin_network_webmail2.zip|d218ed391cb68fdcca9dd50e63b6dba510e581e89f7fe3393c4d06b5a52b5977|Sun Jan 28 14:45:23 2018|200|Sun Jan 28 14:45:23 2018|200|
http://digidom.com/Mailbox/webmail.php|digidom.com|69.89.31.123|||Sun Jan 28 14:45:51 2018|200|||
~~~

## Configuration file
I invite you to read the conf/example.conf file for precise tuning configuration.
Some configurable parameters are:
- search: External source keywords to search for
- log_file: The logging file (the path and file will be created if don't exist)
- Kits_download_Dir: Directory to store downloaded phishing kits archives
- sqliteDB_tablename: Main database table
- sqliteDB_Investig_tablename: Investigation table with useful information for investigations
- http_proxy: HTTP/Socks5 proxy to use for downloads
- UAfile: HTTP user-agents file to use for phishing kits HTTP Get information

## Docker
Build an start the container with docker-composer:
~~~
$ cd docker/
$ docker-compose up --build -d
~~~

The container is configured to keep interesting files into the host's /tmp directory.

You can now execute shell and start launch StalkPhish:
~~~
$ docker exec -ti stalkphish bash
root@stalkphish:/# cd /opt/StalkPhish/stalkphish/
root@stalkphish:/opt/StalkPhish/stalkphish# ./StalkPhish.py -c conf/example.conf 
~~~
