<p align="center"><img src="https://raw.githubusercontent.com/t4d/StalkPhish/master/pics/stalkphish-logo.png"></p>

# StalkPhish
*StalkPhish - The Phishing kits stalker*

**StalkPhish** is a tool created for searching into free OSINT databases for specific phishing kits URL. More, **StalkPhish** is designed to try finding phishing kits sources. Some scammers can't or don't remove their phishing kit sources when they deploy it. You can try to find these sources to extract some useful information as: e-mail addresses/Telegram channel where is send stolen data, some more information about scammer or phishing kit developer. From there you can extend your knowledge about the threat and organizations, and get much useful information for your investigations.

## Features
- find URL where a phishing kit is deployed (from OSINT databases)
- find if the phishing kit is still up and running
- generate hash of page
- try to download phishing kit sources (trying to find .zip file)
- use a hash of the phishing kit archive to identify the kit and threat
- extract e-mails found in phishing kit
- use timestamps for history
- can use HTTP or SOCKS5 proxy (for downloads)
- add just one url at a time into database
- store AS number in database

## Stalkphish.io
[Stalkphish.io](https://stalkphish.io/) is our online Stalkphish infrastructure, making our data available, along with a lot of other information, via a REST API. 

## Blog Posts
You can find some blog posts relatives to phishing and phishing kits on [https://stalkphish.com](https://stalkphish.com/)

## OSINT modules
* [urlscan.io](https://urlscan.io/about-api/) search API
* [urlquery.net](https://urlquery.net/search) search web crawler
* [Phishtank](https://www.phishtank.com/developer_info.php) free OSINT feed (with or without API key)
* [Openphish](https://openphish.com/phishing_feeds.html) free OSINT feed
* [PhishStats](https://phishstats.info/) search API
* [Phishing.Database](https://github.com/mitchellkrogza/Phishing.Database) free OSINT feed

## Requirements
* Python 3
* BeautifulSoup4
* cfscrape
* requests
* PySocks
* lxml

## Online StalkPhish SaaS
You can found our online StalkPhish SaaS application on [https://www.Stalkphish.io](https://www.Stalkphish.io) and use the REST API available for free.

## Join us
You can join us on Keybase: [https://keybase.io/team/stalkphish](https://keybase.io/team/stalkphish) channel 'stalkphish'!

## Upgrade StalkPhish from <0.9.6
Database schema changed (one more time :) for adding the ASnumber, a page hash, and a new column which contains e-mails extracted from Phishing kit's zip, you can modify your existing database like this:
~~~
$ sqlite3 db/StalkPhish.sqlite3 (take care to adapt your tables names)
sqlite> ALTER TABLE StalkPhish ADD COLUMN page_hash TEXT;
sqlite> ALTER TABLE StalkPhish ADD COLUMN ASN TEXT;
sqlite> ALTER TABLE StalkPhishInvestig ADD COLUMN extracted_emails TEXT;
~~~

## Upgrade StalkPhish v0.9 to v0.9.2 (or later)
To update StalPhish v0.9 database, please change your DB schema, to add a new column, like this:
~~~
$ sqlite3 db/StalkPhish.sqlite3
sqlite> ALTER TABLE Investigation_Table_Name ADD COLUMN PageTitle TEXT;
~~~

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

-= StalkPhish - The Phishing Kit stalker - v0.9.8-2 =-


    -h --help       Prints this help
    -c --config     Configuration file to use (mandatory)
    -G --get        Try to download zip file containing phishing kit sources (long and noisy)
    -N --nosint     Don't use OSINT databases
    -u --url        Add only one URL
    -s --search     Search for a specific string on OSINT modules

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

-= StalkPhish - The Phishing Kit stalker - v0.9.8-2 =-

2019-06-18 21:01:16,234 - StalkPhish.py - INFO - Configuration file to use: conf/example.conf
2019-06-18 21:01:16,234 - StalkPhish.py - INFO - Database: ./test/db/StalkPhish.sqlite3
2019-06-18 21:01:16,234 - StalkPhish.py - INFO - Main table: StalkPhish
2019-06-18 21:01:16,235 - StalkPhish.py - INFO - Investigation table: StalkPhishInvestig
2019-06-18 21:01:16,235 - StalkPhish.py - INFO - Files directory: ./test/files/
2019-06-18 21:01:16,235 - StalkPhish.py - INFO - Download directory: ./test/dl/
2019-06-18 21:01:16,235 - StalkPhish.py - INFO - Declared Proxy: socks5://127.0.0.1:9050

2019-06-18 21:01:16,236 - StalkPhish.py - INFO - Proceeding to OSINT modules launch
2019-06-18 21:01:19,102 - urlscan.py - INFO - Searching for 'paypal'...
2019-06-18 21:01:27,460 - urlscan.py - INFO - https://icovil.com/ icovil.com 51.255.74.219 https://urlscan.io/result/25f6bd07-6fac-49af-a6b3-17cbd5fa937c Tue Jun 18 21:01:19 2019 200
2019-06-18 21:01:30,747 - urlscan.py - INFO - http://www.mcseaonline.org/?page_id=4911 www.mcseaonline.org 108.166.135.154 https://urlscan.io/result/a37700f1-86fd-41b2-8c16-5e9b693b7ac8 Tue Jun 18 21:01:27 2019 200
t/38327c8b-a1b9-4919-8037-ddf88238c16c Tue Jun 18 21:03:13 2019 timeout
2019-06-18 21:03:25,836 - urlquery.py - INFO - http://www.killerknuts.com/ www.killerknuts.com 107.180.58.58 https://urlquery.net/report/d9d48c99-dfe5-4002-8a8a-08d44d71ffc2 Tue Jun 18 21:03:20 2019 timeout
2019-06-18 21:03:33,757 - urlquery.py - INFO - https://www.crowdholding.com/ www.crowdholding.com 34.214.183.67 https://urlquery.net/report/b9a09c39-50df-4709-a709-bbcb897c7b96 Tue Jun 18 21:03:25 2019 timeout
2019-06-18 21:03:46,524 - urlquery.py - INFO - http://downlinebooster.ontraport.com/c/s/JZH/jc8b/6/ji/xlj/6hq0Nr/zWarhzzuCJ/P/P/P downlinebooster.ontraport.com 209.170.211.179 https://urlquery.net/report/dc3aa6b1-be7b-409b-8890-7dad962d6063 Tue Jun 18 21:03:33 2019 200
[...]
~~~

## Advanced usage (try to 'G'et phishing kit zipfile, 'N'o OSINT search)
~~~
$ ./StalkPhish.py -c conf/example.conf -G -N

  _____ _        _ _    _____  _     _     _
 / ____| |      | | |  |  __ \| |   (_)   | |    
| (___ | |_ __ _| | | _| |__) | |__  _ ___| |__  
 \___ \| __/ _` | | |/ /  ___/| '_ \| / __| '_ \ 
 ____) | || (_| | |   <| |    | | | | \__ \ | | |
|_____/ \__\__,_|_|_|\__\|    |_| |_|_|___/_| |_|

-= StalkPhish - The Phishing Kit stalker - v0.9.8-2 =-

2019-06-18 20:56:52,818 - StalkPhish.py - INFO - Configuration file to use: conf/example.conf
2019-06-18 20:56:52,818 - StalkPhish.py - INFO - Database: ./test/db/StalkPhish.sqlite3
2019-06-18 20:56:52,818 - StalkPhish.py - INFO - Main table: StalkPhish
2019-06-18 20:56:52,819 - StalkPhish.py - INFO - Investigation table: StalkPhishInvestig
2019-06-18 20:56:52,819 - StalkPhish.py - INFO - Files directory: ./test/files/
2019-06-18 20:56:52,819 - StalkPhish.py - INFO - Download directory: ./test/dl/
2019-06-18 20:56:52,819 - StalkPhish.py - INFO - Declared Proxy: socks5://127.0.0.1:9050

2019-06-18 20:56:52,819 - StalkPhish.py - INFO - Starting trying to download phishing kits sources...
2019-06-18 20:56:55,086 - download.py - INFO - [200] http://donnarogersimagery.com/wp-includes/pomo/login.alibaba.com/
2019-06-18 20:56:56,925 - download.py - INFO - Alibaba Manufacturer Directory - Suppliers, Manufacturers, Exporters &amp; Importers
2019-06-18 20:56:56,934 - download.py - INFO - trying http://donnarogersimagery.com/wp-includes.zip
2019-06-18 20:57:00,663 - download.py - INFO - trying http://donnarogersimagery.com/wp-includes/pomo.zip
2019-06-18 20:57:04,709 - download.py - INFO - trying http://donnarogersimagery.com/wp-includes/pomo/login.alibaba.com.zip
2019-06-18 20:57:12,643 - download.py - INFO - [DL ] Found archive, downloaded it as: ./test/dl/http__donnarogersimagery.com_wp-includes_pomo_login.alibaba.com.zip
2019-06-18 20:57:12,677 - download.py - INFO - [Email] Found: shaddyokoh@hotmail.com
[...]
~~~

## Search usage (Search without touching your configuration file search keyword)
~~~
$ ./StalkPhish.py -c conf/example.conf -s office365

  _____ _        _ _    _____  _     _     _
 / ____| |      | | |  |  __ \| |   (_)   | |    
| (___ | |_ __ _| | | _| |__) | |__  _ ___| |__  
 \___ \| __/ _` | | |/ /  ___/| '_ \| / __| '_ \ 
 ____) | || (_| | |   <| |    | | | | \__ \ | | |
|_____/ \__\__,_|_|_|\__\|    |_| |_|_|___/_| |_|

-= StalkPhish - The Phishing Kit stalker - v0.9.8-2 =-

2019-09-10 17:58:03,141 - StalkPhish.py - INFO - Configuration file to use: conf/example.conf
2019-09-10 17:58:03,142 - StalkPhish.py - INFO - Database: ./db/StalkPhish.sqlite3
2019-09-10 17:58:03,142 - StalkPhish.py - INFO - Main table: StalkPhish
2019-09-10 17:58:03,210 - StalkPhish.py - INFO - Investigation table: StalkPhishInvestig
2019-09-10 17:58:03,279 - StalkPhish.py - INFO - Files directory: ./files/
2019-09-10 17:58:03,279 - StalkPhish.py - INFO - Download directory: ./dl/
2019-09-10 17:58:03,280 - StalkPhish.py - INFO - Declared Proxy: socks5://127.0.0.1:9050

2019-09-10 17:58:03,280 - StalkPhish.py - INFO - Proceeding to OSINT modules launch
2019-09-10 17:58:04,640 - urlscan.py - INFO - Searching for 'office365'...
2019-09-10 17:58:06,862 - urlscan.py - INFO - https://audio209-secondary.z11.web.core.windows.net/xoaksAOKmadjMAoakdamOjasmOADFjoam.xml/VM-memo-ref-29899uo.wav.html%3F audio209-secondary.z11.web.core.windows.net 52.239.146.65 https://urlscan.io/result/f3d6d738-83e5-486b-92d0-f7acd3fc992f Tue Sep 10 17:58:04 2019 404
2019-09-10 17:58:09,427 - urlscan.py - INFO - https://gzbnmd.com/aut1/accounts/active/MTU2ODEyODk2NDJiYmRiNGExNWJjMWUxNDI5YjliYWIzZmJlMjFhMjQ0M2M0OGQ0N2I6a3NjaHViZXJ0QG10Lmdvdg%3D%3D gzbnmd.com 199.188.200.253 https://urlscan.io/result/f95e6302-5d13-4c45-b69e-12de6c5bc06e Tue Sep 10 17:58:06 2019 200
[...]
~~~

## SQLite3 database schema
~~~
$ sqlite3 ./db/StalkPhish.sqlite3 .schema
CREATE TABLE StalkPhish (siteURL TEXT NOT NULL PRIMARY KEY, siteDomain TEXT, IPaddress TEXT, SRClink TEXT, time TEXT, lastHTTPcode TEXT, StillInvestig TEXT, StillTryDownload TEXT, page_hash TEXT, ASN TEST);
CREATE TABLE StalkPhishInvestig (siteURL TEXT NOT NULL PRIMARY KEY, siteDomain TEXT, IPaddress TEXT, ZipFileName TEXT, ZipFileHash TEXT, FirstSeentime TEXT, FirstSeenCode TEXT, LastSeentime TEXT, LastSeenCode TEXT, PageTitle TEXT, extracted_emails TEXT);
~~~

## SQLite3 'main' table sample example
~~~
$ sqlite3 ./db/StalkPhish.sqlite3 'select * from StalkPhish'
https://detoerreoejne.dk/|detoerreoejne.dk|145.239.118.80|https://urlscan.io/result/5b34a3c8-5737-43a4-aad1-87730aff71a8|Tue Jun 18 19:46:25 2019|200||Y|a65b00058ccc76657864fa74accaac5c0b46fa04|16276
https://www.facebook.com/PayPal/?_rdc=1&_rdr|www.facebook.com|157.240.21.35|https://urlscan.io/result/6a0cb6d9-193a-4581-899b-1a24f77ad941|Tue Jun 18 19:46:29 2019|200||Y|14014fdef8dc11407fc4985dc2f35ab73d9cf4b0|32934
https://medium.com/@jhonrabig/watch-ambitions-season-1-episode-1-online-free-720px-9e3eebeab5e4|medium.com|104.16.120.127|https://urlquery.net/report/eb23e4fc-8684-400b-b0e4-df044c5914da|Tue Jun 18 19:46:40 2019|200||Y|27049fba4d5aea74e94b237213e93f33c8e90ee2|13335
https://www.casualfilms.com/|www.casualfilms.com|104.17.128.180|https://urlquery.net/report/c39f40fb-c72f-493d-9b3b-867cbf855659|Tue Jun 18 19:46:43 2019|200||Y|8dfbac8bddd37bb719bf34e7aa60b22714af6b88|13335
https://filecloud.filecloudonline.com/url/j4dja8pupuydjwiz?shareto=secure_message@icradvisor.com|filecloud.filecloudonline.com|34.197.99.39|https://urlquery.net/report/b6ea7ed4-1e77-4688-bd5f-fcb093d5ef62|Tue Jun 18 19:46:45 2019|200||Y|ebddf102f6ac72be2632a5778daf3848509a8901|14618
~~~

## SQLite3 'investigation' table sample example
~~~
$ sqlite3 ./db/StalkPhish.sqlite3 'select * from StalkPhishInvestig'
http://crm.simumak.com/custom/MDP1/aHR0cHM6Ly9jZnNwYXJ0LmltcG90cy5nb3/aWEyLXp1LW1hcGkvamF2YXguZmFjZXMucmVzb3VyY2UvY29tcG9uZW50cy5jc3MueGh0bWw/bG49cHJpbWVmYWNlcyZ2PTYuMQ/Formulaire/72ce7|crm.simumak.com|199.89.53.193|||Sun Jun 16 01:03:24 2019|200|||Particuliers | authentification|
http://muviarts.in/ourtime/ourtimepge|muviarts.in|104.18.54.33|http__muviarts.in_ourtime_ourtimepge.zip|afd48d3db735e861f6a048132b62a4deecfc32a89269b192edbc709563855417|Sun Jun 16 01:03:33 2019|200|Sun Jun 16 01:03:33 2019|200|OurTime.com - The 50+ Single Network|youremailname@domain.com, rzult@otbox.ag
http://twitter-signin.com/|twitter-signin.com|96.47.237.56|||Sun Jun 16 01:03:42 2019|200|||เข้าสู่ระบบทวิตเตอร์ / ทวิตเตอร์|
https://servymain.cl/wp/wp-content/uploads/DP|servymain.cl|200.63.103.27|||Sun Jun 16 01:03:56 2019|200|||Dropbox | Access your documents from any device|
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

You can now execute shell and launch StalkPhish:
~~~
$ docker exec -ti stalkphish sh
/ # cd /opt/StalkPhish/stalkphish/
/opt/StalkPhish/stalkphish # ./StalkPhish.py -c conf/example.conf
~~~

## Demo video
[![StalkPhish v0.9.6 running video](https://img.youtube.com/vi/2YWLZSgrdp0/0.jpg)](https://open.tube/videos/embed/79b9b1eb-4c75-42aa-a519-ee376d0b1341)
