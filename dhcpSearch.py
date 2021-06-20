import re
import sys
import datetime
import csv
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError
import argparse

ELASTIC_INSTANCE = 'localhost'



es = Elasticsearch([{'host': ELASTIC_INSTANCE, 'port': 9200}])
parser = argparse.ArgumentParser()
parser.add_argument("-c", "--csv", help="Send output to CSV file instead of stdout (default)", action="store_true")
File = False
subparsers = parser.add_subparsers(dest = "type", help = "Search type either, ip for IP address search, mac for MAC Addr"
                                                        "ess search, or timestamp for search using both timestamp and ipaddress")
subparsers.required = True
ip_parser = subparsers.add_parser("ip", help = "Search for DHCP entires using ip address")
ip_parser.add_argument('ip_address', help='The ip address to perform the search on, must be in ipv4 or ipv6 address formats')

mac_parser = subparsers.add_parser("mac", help = "Enter the mac address you want to search for")
mac_parser.add_argument('address', help='Enter the Ip address you want to search for')
time_parser = subparsers.add_parser("time", help = "Search for a DHCP record using both IP address and timestamp")
time_parser.add_argument('address',  help='address help')
time_parser.add_argument('timestamp', help='Enter date to start search in YYYY-MM-DD_HH:MM:SS format or now for present')
timesub = time_parser.add_subparsers(dest = "duration", help = 'Choose the duration of the timed search. '
                                                               'The options are hour, day, month, or own if you want to provide '
                                                               '-and end timestamp for the search ')
duration_parser = timesub.add_parser('hour')
duration_parser = timesub.add_parser('day')
duration_parser = timesub.add_parser('month')
duration_parser = timesub.add_parser('year')
duration2_parser = timesub.add_parser('own')
duration2_parser.add_argument('end', help = 'Enter the end date of Search in YYYY-MM-DD_HH:MM:SS format')
args = parser.parse_args()
File = args.csv


def OutputCSV(x):
    sample = x['hits']['hits']
    # then open a csv file, and loop through the results, writing to the csv
    if File:
        with open('outputfile.csv', 'w') as csvfile:
            filewriter = csv.writer(csvfile, delimiter=',',lineterminator='\n',
                                quotechar='|', quoting=csv.QUOTE_MINIMAL)
            filewriter.writerow(["Timestamp", "MAC Address", "IP Address"])
            for hit in sample:
                col1 = hit["_source"]["@timestamp"]
                col2 = hit["_source"]["macaddress"]
                col3 = hit["_source"]["ipaddress"]
                filewriter.writerow([col1,col2,col3])
    else:
        filewriter = csv.writer(sys.stdout, delimiter=',', lineterminator='\n',
                                quotechar='|', quoting=csv.QUOTE_MINIMAL)
        filewriter.writerow(["Timestamp", "MAC Address", "IP Address"])
        for hit in sample:
            col1 = hit["_source"]["@timestamp"]
            col2 = hit["_source"]["macaddress"]
            col3 = hit["_source"]["ipaddress"]
            filewriter.writerow([col1, col2, col3])



def GetIpTime(ip, start, end):
    try:
        result = es.search(index="dhcp", body={"query": {"bool": {"must": [{"match": {"ipaddress": ip}}, {'range' : {'@timestamp': {'gte': start, 'lte': end}}}]}}})
    except NotFoundError:
        return "Not Found"
    return result


def GetMac(mac):
    try:
        result = es.search(index="dhcp", body={"query": {"match": {"macaddress": mac}}})
    except NotFoundError:
        return "Not Found"
    return result


def GetIP(ip):
    try:
        result = es.search(index="dhcp", body={"query": {"match": {"ipaddress": ip}}})
    except NotFoundError:
        return "Not Found"
    return result


if __name__ == "__main__":
    date = re.compile('^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])_(2[0-3]|[01][0-9])(:[0-5][0-9])*(:[0-5][0-9])*$')
    if args.type == "time":
        ip = args.address
        ipv4 = re.compile('^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
        ipv6 = re.compile('^(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)$')
        test4 = ipv4.match(ip)
        test6 = ipv6.match(ip)
        if not test4 and not test6:
            raise argparse.ArgumentTypeError('Incorrect format for ip address, use -h flag for details')
        if args.duration == 'hour':
            toDate = args.timestamp
            if toDate == "now" or toDate == "":
                toDate = "now"
                fromDate = "now-1h"
            else:
                dateTest = date.match(toDate)
                if not dateTest:
                    raise argparse.ArgumentTypeError('Incorrect format for start time, use -h flag for details')
                date_time_obj = datetime.datetime.strptime(toDate, '%Y-%m-%d_%H:%M:%S')
                date_time_obj = date_time_obj - datetime.timedelta(hours=1)
                fromDate = date_time_obj.strftime('%Y-%m-%d %H:%M:%S')
                toDate = toDate[:10]+"T"+toDate[11:]+"Z"
                fromDate = fromDate[:10] + "T" + fromDate[11:] + "Z"
            OutputCSV(GetIpTime(ip, fromDate, toDate))
        elif args.duration == 'day':
            toDate = args.timestamp
            if toDate == "now" or toDate == "":
                toDate = "now"
                fromDate = "now-1d"
            else:
                dateTest = date.match(toDate)
                if not dateTest:
                    raise argparse.ArgumentTypeError('Incorrect format for start time, use -h flag for details')
                date_time_obj = datetime.datetime.strptime(toDate, '%Y-%m-%d %H:%M:%S')
                date_time_obj = date_time_obj - datetime.timedelta(days=1)
                fromDate = date_time_obj.strftime('%Y-%m-%d %H:%M:%S')
                toDate = toDate[:10]+"T"+toDate[11:]+"Z"
                fromDate = fromDate[:10] + "T" + fromDate[11:] + "Z"
            OutputCSV(GetIpTime(ip, fromDate, toDate))
        elif args.duration == 'month':
            toDate = args.timestamp
            if toDate == "now" or toDate == "":
                toDate = "now"
                fromDate = "now-1M"
            else:
                dateTest = date.match(toDate)
                if not dateTest:
                    raise argparse.ArgumentTypeError('Incorrect format for start time, use -h flag for details')
                date_time_obj = datetime.datetime.strptime(toDate, '%Y-%m-%d_%H:%M:%S')
                date_time_obj = date_time_obj - datetime.timedelta(days=30)
                fromDate = date_time_obj.strftime('%Y-%m-%d %H:%M:%S')
                toDate = toDate[:10]+"T"+toDate[11:]+"Z"
                fromDate = fromDate[:10] + "T" + fromDate[11:] + "Z"
            OutputCSV(GetIpTime(ip, fromDate, toDate))
        elif args.duration == "year":
            toDate = args.timestamp
            if toDate == "now" or toDate == "":
                toDate = "now"
                fromDate = "now-1y"
            else:
                dateTest = date.match(toDate)
                if not dateTest:
                    raise argparse.ArgumentTypeError('Incorrect format for start time, use -h flag for details')
                date_time_obj = datetime.datetime.strptime(toDate, '%Y-%m-%d_%H:%M:%S')
                date_time_obj = date_time_obj - datetime.timedelta(days=365)
                fromDate = date_time_obj.strftime('%Y-%m-%d %H:%M:%S')
                toDate = toDate[:10]+"T"+toDate[11:]+"Z"
                fromDate = fromDate[:10] + "T" + fromDate[11:] + "Z"
            OutputCSV(GetIpTime(ip, fromDate, toDate))
        elif args.duration == "own":
            fromDate = args.timestamp
            dateTest = date.match(fromDate)
            if not dateTest:
                raise argparse.ArgumentTypeError('Incorrect format for start time, use -h flag for details')
            toDate = args.end
            dateTest = date.match(toDate)
            if not dateTest:
                raise argparse.ArgumentTypeError('Incorrect format for start time, use -h flag for details')
            toDate = toDate[:10] + "T" + toDate[11:] + "Z"
            fromDate = fromDate[:10] + "T" + fromDate[11:] + "Z"
            OutputCSV(GetIpTime(ip, fromDate, toDate))
    elif args.type == "ip":
        ip = args.address
        ipv4 = re.compile('^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
        ipv6 = re.compile('^(?:(?:[0-9A-Fa-f]{1,4}:){6}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|::(?:[0-9A-Fa-f]{1,4}:){5}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){4}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){3}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,2}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:){2}(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,3}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}:(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,4}[0-9A-Fa-f]{1,4})?::(?:[0-9A-Fa-f]{1,4}:[0-9A-Fa-f]{1,4}|(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(?:(?:[0-9A-Fa-f]{1,4}:){,5}[0-9A-Fa-f]{1,4})?::[0-9A-Fa-f]{1,4}|(?:(?:[0-9A-Fa-f]{1,4}:){,6}[0-9A-Fa-f]{1,4})?::)$')
        test4 = ipv4.match(ip)
        test6 = ipv6.match(ip)
        if test4 or test6:
            OutputCSV(GetIP(ip))
        else:
            raise argparse.ArgumentTypeError('Incorrect format for ip address, use -h flag for details')

    else:
        while(True):
            Mac = input("Enter the Mac address you want to search for: ")
            patMac = re.compile('^(?:[0-9a-fA-F]:?){12}')
            testMac = patMac.match(Mac)
            if testMac:
                break
            else:
                print("Mac address not in the right format try again")
        OutputCSV(GetMac(Mac))
