import subprocess
import argparse

class IpLinux:
    list_name = 'dp_blacklist'

    def __init__(self, filename):
        self.filename = filename

    def list_exists(self, list_name):
        print("at stage 3")
        result = subprocess.run(['sudo', 'ipset', 'list', list_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if "Name:" in result.stdout:
            print("Set can't be created")
            return False
        else:
            print("Set can be created")
            return True

    def create_iplist(self, set_name):
        print("at stage 2")
        if self.list_exists(set_name):
            subprocess.run(['sudo', 'ipset', 'create', set_name, 'hash:ip'])
            print("created iplist")
        return


    def add_ip(self, filename, list_name):
        first_result = subprocess.run(['sudo', 'ipset', 'list', list_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in first_result.stdout.splitlines():
            if line.startswith('Number of entries:'):
                num_entries = line.split(':')[1].strip()
                print(num_entries + " ips are in this list initially")

        with open(filename) as file:
            for ip in file:
                stripped_ip = ip.strip()
                result = subprocess.run(['sudo', 'ipset', 'test', list_name.encode(), stripped_ip.encode()], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if "is NOT in set" in result.stderr:
                    subprocess.run(['sudo', 'ipset', 'add', list_name.encode(), stripped_ip.encode()])
                    print("added ip")
                else:
                    print("Nope")
                    continue
        last_result = subprocess.run(['sudo', 'ipset', 'list', list_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in last_result.stdout.splitlines():
            if line.startswith('Number of entries:'):
                num_entries = line.split(':')[1].strip()
                print(num_entries + " ips are in this list finally")
    def add_rule(self, list_name):
        list_name_encoded = list_name.encode()
        result = subprocess.run(['sudo', 'iptables', '-S'], stdout=subprocess.PIPE, text=True)
        rules = result.stdout.splitlines()
        exists = False
        print(list_name_encoded)
        for rule in rules:
            if "INPUT -m set --match-set {} ".format(list_name) in rule and "DROP" in rule:
                print(list_name + " already in")
                exists = True
        if exists == False:
            subprocess.run(['sudo', 'iptables', '-I', 'INPUT', '-m', 'set', '--match-set', list_name_encoded, 'src', '-j', 'DROP'])
            print("added rule")
            return
    def display_results(self, filename, list_name):
        line_number = sum(1 for line in open(filename))
        result2 = subprocess.run(['sudo', 'iptables', '-S'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        rules = result2.stdout.splitlines()
        for rule in rules:
            if list_name + " " in rule:
                print(rule)
        print("line numbers in doc is " + str(line_number))
    def do_all(self, filename):
        print("at stage 1")
        self.create_iplist(IpLinux.list_name)
        self.add_ip(filename, IpLinux.list_name)
        self.add_rule(IpLinux.list_name)
        self.display_results(filename, IpLinux.list_name)


def class_func(filename):
    print("before all")
    obj1 = IpLinux(filename)
    print("before stage 1")
    obj1.do_all(filename)


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

# do all, dp-blacklist fixed value, pass in ip address text file
# make into class, shared variable put as class v