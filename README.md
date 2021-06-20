# InfoSecScripts
Non-confidential Stony Brook Information Security scripts


## Automating "Botnet" Report - botnet.py
Uses Gmail API to download pdf firewall logs and coverts contents to csv then sends an email to the ticketing system for lines that match a criteria. Users that hit a malicious site over 100 times most likely have malware on their system. Users that met this critera recently are ignored to avoid creating duplicate tickets.


## Proof of conecpt ElasticSearch for log aggregation - dhcpsearch.py
The script allows information security professionals to query DHCP logs for useful data being aggregated in ElasticSearch instace I established.
