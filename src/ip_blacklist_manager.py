import subprocess
import argparse
import re




def is_valid_ip(ip):
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')

    if ip_pattern.match(ip):
        parts = ip.split('.')
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        return True
    return False


class BlackListManager:
    """BlackListManager is responsible for managing a list of IP addresses to be blacklisted on a linux remote server firewall。 Internally uses Linux commands iptables/ipset
    This class provides functionalities to:

    1. Create an ip list
    2. Check if IP list exists
    3. Add an IP to the IP list
    4. Add a rule blocking the blacklist
    5. Displaying all results"""

    iplist = 'dp_blacklist'

    def __init__(self, ip_list_file):
        self.ip_list_file = ip_list_file
        self.valid_ip_count = 0
        self.ips_in_ipset = 0

    def list_exists(self):
        result = subprocess.run(['sudo', 'ipset', 'list', self.iplist], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True)
        if "Name:" in result.stdout:
            print(f"{self.iplist} already exists")
            return False
        else:
            print("Set can be created")
            return True

    def create_iplist(self):
        if self.list_exists():
            subprocess.run(['sudo', 'ipset', 'create', self.iplist, 'hash:ip'])
            print(f"{self.iplist} has been created in the ipset")
        return

    def add_ip_ipset(self):
        first_result = subprocess.run(['sudo', 'ipset', 'list', self.iplist], stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, text=True)
        for line in first_result.stdout.splitlines():
            if line.startswith('Number of entries:'):
                num_entries = line.split(':')[1].strip()
                print(f"{num_entries} ips are in this list initially")
                break

        with open(self.ip_list_file) as file:
            for ip in file:
                stripped_ip = ip.strip()
                if is_valid_ip(stripped_ip):
                    self.valid_ip_count += 1
                    result = subprocess.run(['sudo', 'ipset', 'test', self.iplist.encode(), stripped_ip.encode()],
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    if "is NOT in set" in result.stderr:
                        subprocess.run(['sudo', 'ipset', 'add', self.iplist.encode(), stripped_ip.encode()])
                        print(f"{stripped_ip} added")
                        break
                    else:
                        print(f"{stripped_ip} already in {self.iplist}")
        last_result = subprocess.run(['sudo', 'ipset', 'list', self.iplist], stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
        for line in last_result.stdout.splitlines():
            if line.startswith('Number of entries:'):
                num_entries = line.split(':')[1].strip()
                self.ips_in_ipset = int(num_entries)
                break

    def add_rule(self):
        list_name_encoded = self.iplist.encode()
        result = subprocess.run(['sudo', 'iptables', '-S'], stdout=subprocess.PIPE, text=True)
        rules = result.stdout.splitlines()
        exists = False
        for rule in rules:
            if "INPUT -m set --match-set {} ".format(self.iplist) in rule and "DROP" in rule:
                print(f"{self.iplist} already in")
                exists = True
        if not exists:
            subprocess.run(
                ['sudo', 'iptables', '-I', 'INPUT', '-m', 'set', '--match-set', list_name_encoded, 'src', '-j', 'DROP'])
            print("added rule")
            return

    def display_results(self):
        ip_rules_result = subprocess.run(['sudo', 'iptables', '-S'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         text=True)
        rules = ip_rules_result.stdout.splitlines()
        for rule in rules:
            if "match-set " + self.iplist + " " in rule:
                print(rule)
        print("line numbers in doc is " + str(self.valid_ip_count))
        print(f"{self.ips_in_ipset} ips are in this {self.ip_list_file}]")

    def do_all(self):
        self.create_iplist()
        self.add_ip_ipset()
        self.add_rule()
        self.display_results()



if __name__ == "__main__":
    # test_is_valid_ip()
    parser = argparse.ArgumentParser(description='Run specific functions with parameters.')
    parser.add_argument('function', type=str, help='The function to call')
    parser.add_argument('params', nargs='*', help='The parameters to pass to the function')
    args = parser.parse_args()


    def block_ips(filename):
        obj1 = BlackListManager(filename)
        obj1.do_all()


    if args.function == 'block_ips':
        if len(args.params) != 1:
            print("block_ips requires 1 parameter")
        else:
            block_ips(args.params[0])
