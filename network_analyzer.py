import socket
import ipaddress

from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
from rich.console import Console
from rich.table import Table

class NetworkAnalyzer:
    def __init__(self, network_range, timeout=1):
        self.network_range = network_range
        self.timeout = timeout

    def _scan_host_sockets(self, ip, port=1000):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((ip, port))
                return (ip, True)
        except (socket.timeout, socket.error):
            return (ip, False)

    def hosts_scan(self, port=1000):
        network = ipaddress.ip_network(self.network_range, strict=False)
        hosts_up = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = { executor.submit(self._scan_host_sockets, str(host), port): host for host in tqdm(network.hosts(), desc='Escaneando host') }
            for future in tqdm(futures, desc='Obteniendo resultados'):
                if future.result()[1]:
                    hosts_up.append(future.result()[0])

        return hosts_up

    def pretty_print(self, data, data_type='hosts'):
        console = Console()
        table = Table(show_header=True, header_style='bold magenta')

        if data_type == 'hosts':
            table.add_column('Host Up', style='bold green')
            for host in data:
                table.add_row(host, end_section=True)
        console.print(table)
