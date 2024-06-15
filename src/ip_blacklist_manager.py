import subprocess
import argparse

class BlackListManager:
    """IpLinux is responsible for managing a list of IP addresses to be blacklisted on a linux remote server firewall
    This class provides functionalities to:

    1. Create an IP List
    2. Check if IP list exists
    3. Add an IP to the IP list
    4. Add a rule blocking the blacklist
    5. Displaying all results"""

    iplist = 'dp_blacklist'

    def __init__(self, ip_list_file):
        self.ip_list_file = ip_list_file

    def list_exists(self):
        result = subprocess.run(['sudo', 'ipset', 'list', self.iplist], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "Name:" in result.stdout:
            print("Set can't be created")
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
        first_result = subprocess.run(['sudo', 'ipset', 'list', self.iplist], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in first_result.stdout.splitlines():
            if line.startswith('Number of entries:'):
                num_entries = line.split(':')[1].strip()
                print(num_entries + " ips are in this list initially")

        with open(self.ip_list_file) as file:
            for ip in file:
                stripped_ip = ip.strip()
                result = subprocess.run(['sudo', 'ipset', 'test', self.iplist.encode(), stripped_ip.encode()], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if "is NOT in set" in result.stderr:
                    subprocess.run(['sudo', 'ipset', 'add', self.iplist.encode(), stripped_ip.encode()])
                    print(f"{stripped_ip} added")
                else:
                    print("IP already in set")
                    continue
        last_result = subprocess.run(['sudo', 'ipset', 'list', self.iplist], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in last_result.stdout.splitlines():
            if line.startswith('Number of entries:'):
                num_entries = line.split(':')[1].strip()
                print(f"{num_entries} ips are in this list finally")
                break
    def add_rule(self):
        list_name_encoded = self.iplist.encode()
        result = subprocess.run(['sudo', 'iptables', '-S'], stdout=subprocess.PIPE, text=True)
        rules = result.stdout.splitlines()
        exists = False
        print(list_name_encoded)
        for rule in rules:
            if "INPUT -m set --match-set {} ".format(self.iplist) in rule and "DROP" in rule:
                print(self.iplist + " already in")
                exists = True
        if exists == False:
            subprocess.run(['sudo', 'iptables', '-I', 'INPUT', '-m', 'set', '--match-set', list_name_encoded, 'src', '-j', 'DROP'])
            print("added rule")
            return
    def display_results(self):
        line_number = sum(1 for line in open(self.ip_list_file))
        ip_rules_result = subprocess.run(['sudo', 'iptables', '-S'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        rules = ip_rules_result.stdout.splitlines()
        for rule in rules:
            if self.iplist + " " in rule:
                print(rule)
        print("line numbers in doc is " + str(line_number))
    def do_all(self):
        print("at stage 1")
        self.create_iplist()
        self.add_ip_ipset()
        self.add_rule()
        self.display_results()


def class_func(filename):
    obj1 = BlackListManager(filename)
    obj1.do_all()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run specific functions with parameters.')
    parser.add_argument('function', type=str, help='The function to call')
    parser.add_argument('params', nargs='*', help='The parameters to pass to the function')
    args = parser.parse_args()

    if args.function == 'class_func':
        if len(args.params) != 1:
            print("class_func requires 1 parameter")
        else:
            class_func(args.params[0])