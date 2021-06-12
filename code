from scapy.all import *
from threading import Thread
import pandas
import time
import os

# initializing the networks dataframe
networks = pandas.DataFrame(columns=["BSSID", "SSID", "dBm_Signal", "Channel", "Crypto"])
# code to set the index BSSID (MAC address of the AP)
networks.set_index("BSSID", inplace=True)

def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # code to extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # code to get the name of it
        ssid = packet[Dot11Elt].info.decode()
        try:
            dbm_signal = packet.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # code to extract network stats
        stats = packet[Dot11Beacon].network_stats()
        # code to get the channel of the AP
        channel = stats.get("channel")
        # code to get the crypto
        crypto = stats.get("crypto")
        networks.loc[bssid] = (ssid, dbm_signal, channel, crypto)


def print_all():
    while True:
        os.system("clear")
        print(networks)
        time.sleep(0.8)


def change_channel():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 0.8s
        ch = ch % 14 + 1
        time.sleep(0.8)


if __name__ == "__main__":
    # interface name, check using iwconfig
    interface = "wlan0mon"
    # code for a thread that prints all the networks
    printer = Thread(target=print_all)
    printer.daemon = True
    printer.start()
    # code for channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    # code for initialising sniffer 
    sniff(prn=callback, iface=interface)
