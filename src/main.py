#!/usr/bin/env python3

from enum import Enum
import click

"""
    Surikatz

    A powerful tool for searching informations before pentest.

    Can be used as 3 way :
      * Passive : Only search on public sources (Shodan, TheHarvester, VeryLeaks...)
      * Discrete : Use Passsive technics and soft nmap scan, soft HTTrack...
      * Agressive : Use Passive and Discrete technics but more... agressive.
                   Use nmap NSE scrips for firewall, WAF, IDS detection and evasion, enumeration for kerberos...

    Usage:
        ./surikatz [IP/FQDN] [Options]

    Authors:
        Abdelmalik KERBADOU
        Théo PERESSE-GOURBIL
        Manon HERMANN
        Rayane BOUDJEMAA
        Nathan SAUCET
        Laurent DELATTE
"""

class ScanMode(Enum):
    PASSIVE = 0
    DISCRET = 1
    AGRESSIVE = 2

@click.command()
@click.argument("target")
@click.option("-a", "--agressive", "level", flag_value=ScanMode.AGRESSIVE, type=ScanMode, default=ScanMode.AGRESSIVE, help="Use Discret and vulerability scanner, ennumeration and bruteforce")
@click.option("-d", "--discret", "level", flag_value=ScanMode.DISCRET, type=ScanMode, default=ScanMode.AGRESSIVE, help="Use passive mode with soft scans")
@click.option("-p", "--passive", "level", flag_value=ScanMode.PASSIVE, type=ScanMode, default=ScanMode.AGRESSIVE, help="Use only OSINT technics to retrive data")
def launch(target, level):
    if level == ScanMode.PASSIVE:
        print("Mode passif")
    if level == ScanMode.DISCRET:
        print("Mode discret")
    if level == ScanMode.AGRESSIVE:
        print("Mode agressif")

if __name__ == '__main__':
    launch()
