# InfoSecScripts
Non-confidential Stony Brook Information Security scripts


## Automating "Botnet" Report
Uses Gmail API to download pdf firewall logs and coverts contents to csv then sends an email to the ticketing system for lines that match a criteria. Users that hit a malicious site over 100 times most likely have malware on their system. Users that met this critera recently are ignored to avoid creating duplicate tickets.
