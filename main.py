from network_analyzer import NetworkAnalyzer

if __name__ == '__main__':
    analyzer = NetworkAnalyzer('192.168.1.12/24')
    hosts_up = analyzer.hosts_scan(80)
    analyzer.pretty_print(hosts_up)