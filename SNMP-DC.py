import concurrent.futures
from scapy.all import ARP, Ether, srp
from pysnmp.hlapi import *
import openpyxl

def scan_subnet(subnet):
    ip_list = []
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=3, verbose=0)[0]

    for sent, received in result:
        ip_list.append(received.psrc)

    print(f"Found hosts in {subnet}: {ip_list}")
    return ip_list

def snmp_query(ip, oid):
    iterator = getCmd(
        SnmpEngine(),
        CommunityData('public', mpModel=0),
        UdpTransportTarget((ip, 161), timeout=1, retries=3),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:
        print(f"Error: {errorIndication} for IP {ip}, OID {oid}")
        return None
    elif errorStatus:
        print(f"{ip}: {errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}")
        return None
    else:
        for varBind in varBinds:
            print(f"SNMP query result for {ip}, OID {oid}: {varBind[1].prettyPrint()}")
            return varBind[1].prettyPrint()
    return None

def collect_printer_data(ip):
    data = {}
    oids = {
        'model': '1.3.6.1.2.1.1.1.0',
        'counter': '1.3.6.1.2.1.43.10.2.1.4.1.1',
        'serial_number': '1.3.6.1.2.1.43.5.1.1.17.1'
    }

    for key, oid in oids.items():
        result = snmp_query(ip, oid)
        if result is not None:
            data[key] = result

    if data:
        print(f"Collected data for {ip}: {data}")
        return data
    else:
        return None

def scan_and_collect(subnet):
    hosts_data = []
    hosts = scan_subnet(subnet)

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(collect_printer_data, host): host for host in hosts}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                data = future.result()
                if data:
                    hosts_data.append((host, data))
            except Exception as e:
                print(f"Error collecting data from host {host}: {e}")

    return hosts_data

def write_to_excel(data):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["IP", "Model", "Counter", "Serial Number"])

    for host, printer_data in data:
        ws.append([host, printer_data.get('model'), printer_data.get('counter'), printer_data.get('serial_number')])

    wb.save("printers_data.xlsx")
    print("Data saved to printers_data.xlsx")

def main(subnets):
    all_data = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(scan_and_collect, subnet) for subnet in subnets]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                all_data.extend(result)

    print(f"All collected data: {all_data}")
    write_to_excel(all_data)

if __name__ == "__main__":
    subnets = ["172.16.0.0/16", "192.168.100.0/24"]
    main(subnets)
