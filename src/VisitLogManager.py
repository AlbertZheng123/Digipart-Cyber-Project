import re
from datetime import datetime
import argparse
import os
import gzip


class Log2Blacklist:

    class VisitorLog:
        def __init__(self):
            self.information = {}

        def add_info(self, ip, timestamp):
            if ip in self.information:
                self.information[ip].append(timestamp)
            else:
                self.information[ip] = [timestamp]

    def read_apache_log(self, filename):
        line_count = 0
        directory = "apache_log"
        os.chdir(directory)
        log = self.VisitorLog()
        log_pattern = re.compile(r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<timestamp>[^\]]+)\]')
        with gzip.open(filename, 'rb') as apache_log:
            for line in apache_log:
                line = line.decode('utf-8')
                match = log_pattern.match(line)
                if match:
                    line_count += 1
                    ip = match.group('ip')
                    timestamp_str = match.group('timestamp')
                    timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
                    log.add_info(ip, timestamp)
                    if line_count >= 300:
                        break
        for key, value in log.information.items():
            print(f"Key: {key}, Value: {value}")
        return log


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run specific functions with parameters.')
    parser.add_argument('function', type=str, help='The function to call')
    parser.add_argument('params', nargs='*', help='The parameters to pass to the function')
    args = parser.parse_args()
    if args.function == 'read_apache_log':
        if len(args.params) != 1:
            print("block_ips requires 1 parameter")
        else:
            VisitLogObject = Log2Blacklist()
            VisitLogObject.read_apache_log(args.params[0])

