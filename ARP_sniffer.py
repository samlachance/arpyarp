from scapy.all import *
import time

# Sets time vars that will be used to weed out duplicates
gregtime = time.time()
tobytime = time.time()

def arp_display(pkt):
  global gregtime
  global tobytime

  if pkt[ARP].op == 1: #who-has request
    if pkt[ARP].hwsrc == '44:65:0d:f7:6d:34': # Dash button 1 (Greg)
      if time.time() - gregtime > 2: # Compares current time to the previously set time. 
        print "Hello from Greg" # Code
        gregtime = time.time() # Sets the old time to the current time.
    elif pkt[ARP].hwsrc == '44:65:0d:fa:89:a4': # Dash button 2 (Toby)
      if time.time() - tobytime > 2:
        print "Hello from Toby"
        tobytime = time.time()

sniff(prn=arp_display, filter="arp", store=0, count=0) # Scapy sniff command.