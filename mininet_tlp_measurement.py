#!/usr/bin/python 

from mininet.topo import Topo
from mininet.link import TCLink
from mininet.net import Mininet
from time import sleep
from mininet.node import Node
import argparse
import drop_tail

class router(Topo):
    #link with different values of bandwidth and latency
    linkopts1 = dict(bw=1, delay='5ms')
    linkopts2 = dict(bw=0.5, delay='10ms')
    linkopts3 = dict(bw=0.1, delay='20ms')

    def __init__(self, choice, **opts):
        Topo.__init__(self, **opts)
        print('Adding hosts')
        h1 = self.addHost( 'h1' )
        h2 = self.addHost( 'h2' )
        h3 = self.addHost( 'h3' )
        print('Adding links')
        if(choice=='fast'):
            self.addLink(h1,h2, use_tbf=True, **self.linkopts1)
            self.addLink(h2,h3, use_tbf=True, **self.linkopts1)
        elif(choice=='moderate'):
            self.addLink(h1,h2, use_tbf=True, **self.linkopts2)
            self.addLink(h2,h3, use_tbf=True, **self.linkopts2)
        elif(choice=='slow'):
            self.addLink(h1,h2, use_tbf=True, **self.linkopts3)
            self.addLink(h2,h3, use_tbf=True, **self.linkopts3)
        else:
            self.addLink(h1,h2, use_tbf=True)
            self.addLink(h2,h3, use_tbf=True)


def project(choice, buffsize, destfile, segments):
    topo = router(choice)
    net = Mininet(topo=topo, link=TCLink)
    print('Starting network...')
    net.start()
    print('Network started!')

    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')

    #the configuration of hosts
    h1.cmd('ifconfig h1-eth0 10.0.0.1 netmask 255.255.255.0')
    h2.cmd('ifconfig h2-eth0 10.0.0.2 netmask 255.255.255.0')
    h2.cmd('ifconfig h2-eth1 10.0.1.2 netmask 255.255.255.0')
    h3.cmd('ifconfig h3-eth0 10.0.1.3 netmask 255.255.255.0')

    h1.cmd('route add default gw 10.0.0.2')
    h3.cmd ('route add default gw 10.0.1.2')
    #Activating the forward mode at host B
    h2.cmd('sysctl net.ipv4.ip_forward=1')

    #ping between hosts
    print('ping h1 - > h3')
    print h1.cmd('ping -c5 10.0.1.3')
    #nc6 and tcpdump
    nc6TCPd(h1, h2, h3, transferSize(buffsize), destfile, segments)

    net.stop()
    print ('Network stopped!')

def netfilter(h2, segments, bfs):
	h2.cmd('iptables -A FORWARD -i h2-eth0 -o h2-eth1 -p tcp -j NFQUEUE --queue-num 0')
	print('I am here')
	result=h2.cmd('python drop_tail.py --transfer 33 --segments 22')
	print(result)
	
	
def nc6TCPd(h1, h2, h3, bfs, destfile, segments):
    h2.cmd('mkdir captures')

    print('Netcat6')
    h1.sendCmd('dd if=/dev/zero bs=1448 count='+ str(bfs) + ' | nc6 -4 -X -l -p 7676 &')

    dest='test'
    if destfile:
        dest = destfile
    print('TCPDUMPing')
    h2.cmd('tcpdump -p -s 68 -w captures/'+ str(dest) +'.pcap -i h2-eth0 &')

    sleep(1)
    print('Netcat6 started!')    
    print h3.sendCmd('nc6 -4 --rev-transfer ' + h1.IP() +' 7676 > /dev/null')
    print('Sleep 10 seconds')
    sleep(1)
    #print('NET FILTER start')
    #netfilter(h2, segments, bfs)
    #print('NET FILTER end')
    h3.waitOutput()    
    h1.waitOutput()
	
    #netfilter(h2,segments,bfs)

    h2.cmd('kill %tcpdump')
    sleep(1)

    print('Transfer finished!')
    print('NET FILTER start')
    netfilter(h2, segments, bfs)
    sleep(5)
    print('NET FILTER end')


def transferSize(bufferSize):
    if bufferSize=='short':
	return 64
    elif bufferSize=='medium':
	return 128
    elif bufferSize=='long':
	return 256
    else:
	return 64
  


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Specify Config")
    parser.add_argument('--config', '-c', help='Configure link')
    parser.add_argument('--transfer', '-t', help='Transfer Size')
    parser.add_argument('--dest', '-d', help='Packets destination File')
    parser.add_argument('--segments', '-s', help='Number of dropped segments')
    args = parser.parse_args()
    project((args.config), (args.transfer), (args.dest), (args.segments))

