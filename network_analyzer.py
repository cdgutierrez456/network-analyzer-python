import socket
import ipaddress

from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

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

    def hosts_scan(self, port):
        network = ipaddress.ip_network(self.network_range, strict=False)
        hosts_up = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = { executor.submit(self._scan_host_sockets, str(host), port): host for host in tqdm(network.hosts(), desc='Escaneando host') }
            for future in tqdm(futures, desc='Obteniendo resultados'):
                if future.result()[1]:
                    hosts_up.append(future.result()[0])

        return hosts_up
