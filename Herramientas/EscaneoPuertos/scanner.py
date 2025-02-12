#!/usr/bin/env python3

from pwn import * 
from scapy.all import *
from termcolor import colored

import signal
import sys
import time
import threading

# Solamente mostrar errores criticos 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

p1 = log.progress("TCP Scan")
p1.status("Escaneando Puertos...")

def def_handler(sig,frame):
    p1.failure("Escaneo abortado")
    print(colored(f"\n\n[!] Saliendo...\n",'red'))
    sys.exit(1)

#Ctrl+c
signal.signal(signal.SIGINT, def_handler)

def scanPort(ip,port):

    src_port = RandShort()

    try:

        response = sr1(IP(dst=ip)/TCP(sport=src_port, dport=port, flags="S"), timeout=2, verbose=0)

        if response is None:
            return False
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            
            send(IP(dst=ip)/TCP(sport=src_port, dport=port, flags="R"), verbose = 0)
            return True

        else:
            return False

    except Exception as e:
        log.failure(f"Error escaneando {ip} en puerto {port}: {e}")
        sys.exit(1)

def thread_function(ip,port):

    response = scanPort(ip,port)

    if response:
        print(f"Puerto {port} - Abierto")

def main(ip, ports, end_port):

    threads = []
    time.sleep(2)

    for port in ports:
        
        p1.status(f"Progreso del escaneo: [{port}/{end_port}]")

        thread = threading.Thread(target=thread_function, args=(ip,port))
        thread.start()
        threads.append(thread)

        for thread in threads:
            thread.join()

    p1.success("Escaneo finalizado")

if __name__ == '__main__':

    if len(sys.argv) != 3:
        print(colored(f"\n\n[!] Uso: {colored("python3",'blue')} {colored(sys.argv[0],'green')} {colored("<ip> <ports-range>\n",'yellow')}",'red'))
        sys.exit(1)

    target_ip = sys.argv[1]
    portRange = sys.argv[2].split("-")
    start_port = int(portRange[0])
    end_port = int(portRange[1])

    ports = range(start_port, end_port + 1)

    main(target_ip, ports, end_port)

