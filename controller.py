from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP
from async_sniff import sniff
from cpu_metadata import CPUMetadata
from collections import namedtuple
from pwospf import Pwospf, Hello, LSU
from pwospf_interfaces import PwospfIntf
from topo_database import TopoDatabase
import time
import copy

CPU_TYPE = 0x080a
ARP_TYPE = 0x0806
ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002
PWOSPF_TYPE_HELLO = 0x01
PWOSPF_TYPE_LSU   = 0x04
#Pwospf_intf = namedtuple('Pwospf_intf', ['ip', 'mask', 'helloint', 'neighbors'])
#Pwospf_neighbor = namedtuple('Pwospf_neighbor', ['id', 'ip'])

#MAX_INTF = 8

class MacLearningController(Thread):
	def __init__(self, sw, areaId, routerId, start_wait=0.3):
		super(MacLearningController, self).__init__()
		self.sw = sw
		self.mac = sw.MAC()
		self.start_wait = start_wait # time to wait for the controller to be listenning
		self.iface = sw.intfs[1].name
		self.port_for_mac = {}
		self.mac_for_ip = {}
		self.stop_event = Event()
	
		self.arpQueue = {}

		# PWOPSF Router Metadata
		self.routerId = routerId
		self.areaId = areaId
		self.lsuint = 60; # 60 seconds between each link status update broadcast
		self.mask = '255.255.255.0'
		self.routerBaseIp = '10.0.' + str(routerId) + '.0'
		self.neighborInfo = {}

		# Set up Topology Database
		self.networkTopo = TopoDatabase(routerId, self.lsuint, self.neighborInfo, sw)  #TODO: Uncomment this
		self.lsuSeqList = {}

		# Initialize pwospf interfaces
		self.pwospfIntf = PwospfIntf(sw, routerId, areaId, self.lsuint, self.networkTopo, self.neighborInfo)

		#TODO: Make sure to always identify all hosts before pinging across subnets
		#TODO: Or just have generic handler
		sw.insertTableEntry(table_name='MyIngress.fwd_ip',
				match_fields={'hdr.ipv4.dstAddr': [self.routerBaseIp, 24]},
				action_name='MyIngress.send_to_cpu',
				action_params={})

	def addMacAddr(self, mac, port, ip):
		# Don't re-add the mac-port mapping if we already have it:
		if mac in self.port_for_mac: return

		self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
			match_fields={'hdr.ethernet.dstAddr': [mac]},
			action_name='MyIngress.set_egr',
			action_params={'port': port})
		self.port_for_mac[mac] = port

		self.sw.insertTableEntry(table_name='MyIngress.arp_cache',
			match_fields={'hdr.arp.dstIP': [ip]},
			action_name='MyIngress.return_arp',
			action_params={'cachedMac': mac})
		
		self.sw.insertTableEntry(table_name = 'MyIngress.fwd_ip', match_fields = {'hdr.ipv4.dstAddr': [ip, 32]}, action_name = 'MyIngress.ipv4_fwd', action_params = {'mac': mac, 'port': 0})
		self.mac_for_ip[ip] = mac
		#self.sw.insertTableEntry(table_name='MyIngress.fwd_ip',
		#	match_fields={'hdr.ipv4.dstAddr': [ip, 32]},
		#	action_name='MyIngress.ipv4_fwd',
		#	action_params={'mac': mac})
	
	def convertIPtoSubnet(self, ip, mask): 
		#print('converting!') 
		ipComponents = ip.split('.') 
		maskComponents = mask.split('.') 
		subnetComponents = [] 
		for i in range(4): 
			subnetComponents.append(str(int(ipComponents[i]) & int(maskComponents[i])))      
		subnet = '.'.join(subnetComponents) 
		return subnet
		#print(ip + '->' + subnet)

	def checkSubnetEquivalence(self, ip1, ip2): 
		subnet1 = self.convertIPtoSubnet(ip1, self.mask) 
		subnet2 = self.convertIPtoSubnet(ip2, self.mask)
		#print(subnet1)
		#print(subnet2)
		#print(subnet1 == subnet2)
		return subnet1 == subnet2
		

	def handleArpReply(self, pkt):
		#pkt.show2()
		self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort, pkt[ARP].psrc)
		# TODO: Check if reply matches what is in queue
		if(pkt[ARP].pdst == self.routerBaseIp):
			ipsrc = pkt[ARP].psrc
			if(ipsrc in self.arpQueue):
				queuedPkt = self.arpQueue[ipsrc]
				queuedPkt[Ether].dst = pkt[ARP].hwsrc
				self.send(queuedPkt)
				del self.arpQueue[ipsrc]
		else:
			self.send(pkt)

	def handleArpRequest(self, pkt):
		#pkt.show2()
		#print('routerid: ' + str(self.routerId))
		targetIp = pkt[ARP].pdst

		if(self.checkSubnetEquivalence(targetIp, self.routerBaseIp)): # Packet IPdst is in the current subnet
			#print("nice")
			self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort, pkt[ARP].psrc)		
			self.send(pkt)
			return
		
		# Arp requests for hosts outside of current subnet return the current router macAddress
		copyPkt = copy.deepcopy(pkt)
		self.addMacAddr(copyPkt[ARP].hwsrc, copyPkt[CPUMetadata].srcPort, copyPkt[ARP].psrc)
		pkt[Ether].dst = pkt[Ether].src
		pkt[Ether].src = self.mac
		pkt[ARP].op = 2
		temp = pkt[ARP].psrc
		pkt[ARP].psrc = pkt[ARP].pdst
		pkt[ARP].pdst = temp
		pkt[ARP].hwdst = pkt[ARP].hwsrc
		pkt[ARP].hwsrc = self.mac
		#pkt.show2()
		
		self.send(pkt)

	def verifyPwospfChecksum(self, pkt):
		# TODO: Establish this
		return True	

	#def handleHello(self, pkt, intf, routerId): 
	#	if(pkt[Hello].networkMask != intf.mask): return 
	#	if(pkt[Hello].helloInt != intf.helloint): return 
	#	srcIP = pkt[IP].src;
	#	if srcIP not in intf.neighbors:
	#		intf.neighbors[srcIP] = routerId;
	#		print(srcIP, routerId)
	#	else:
	#		# Update Last Hello Packet Received Timer 
	#		pass
	def handleHello(self, pkt):
		assert Hello in pkt
		self.pwospfIntf.handleHelloPkt(pkt)

	def handleLSU(self, pkt):
		assert LSU in pkt
		pktRouterId = pkt[Pwospf].routerId
		pktSeqNum = pkt[LSU].seq
		if(pktRouterId not in self.lsuSeqList):
			self.lsuSeqList[pktRouterId] = pktSeqNum
		elif(pktSeqNum <= self.lsuSeqList[pktRouterId]): 
			return # Drop duplicate lsu packets
		else:
			self.lsuSeqList[pktRouterId] = pktSeqNum
		self.networkTopo.handleLSUPkt(pkt)
		if(pkt[LSU].ttl > 1): # Packet should be flooded if ttl is greater than 1
			pkt[LSU].ttl -= 1
			sendList = self.pwospfIntf.getFloodPacketList(pkt)
			if(sendList):
				#print(self.routerId)
				#sendList[0].show2()
				for sendPkt in sendList:
					self.send(sendPkt)	
	
	def verifyIPChecksum(self, pkt):
		#TODO: Calculate this
		return True
			
	def handlePwospf(self, pkt):
		if(pkt[IP].version != 4): return
		if(not self.verifyIPChecksum(pkt)): return
		if(pkt[Pwospf].version != 2): return
		if(pkt[Pwospf].areaId != self.areaId): return
		if(pkt[Pwospf].auType != 0): return
		if(not self.verifyPwospfChecksum(pkt)): return
		if(pkt[Pwospf].routerId == self.routerId): return
	
		#intf = self.pwospf_intfs[srcPort - 1]
		#srcPort = pkt[CPUMetadata].srcPort
		#pktRouterId = pkt[Pwospf].routerId
		#srcIP = pkt[IP].src
		if pkt[Pwospf].type == PWOSPF_TYPE_HELLO:
			self.handleHello(pkt)
			#self.handleHello(pkt, intf, routerId)
			#self.pwospfIntf.handleHelloPkt(pkt)
		elif pkt[Pwospf].type == PWOSPF_TYPE_LSU:
			self.handleLSU(pkt)


	def handleMissingIP(self, pkt):
		if(pkt[IP].version != 4): return
		if(not self.verifyIPChecksum(pkt)): return

		self.arpQueue[pkt[IP].dst] = pkt
		# TODO: Send out arp request
		arpRequestPkt = Ether(dst="ff:ff:ff:ff:ff:ff", src=self.mac, type=CPU_TYPE)/CPUMetadata(fromCpu=1, origEtherType=ARP_TYPE)/ARP(hwsrc=self.mac, psrc=self.routerBaseIp, hwdst='00:00:00:00:00:00', pdst=pkt[IP].dst)
		#print("this is important!")
		#arpRequestPkt.show2()
		self.send(arpRequestPkt)
		

	def handlePkt(self, pkt):
		#pkt.show2()
		assert CPUMetadata in pkt, "Should only receive packets from switch with special header"

		# Ignore packets that the CPU sends:
		if pkt[CPUMetadata].fromCpu == 1: return
		#pkt.show2()

		if ARP in pkt:
			if pkt[ARP].op == ARP_OP_REQ:
				self.handleArpRequest(pkt)
			elif pkt[ARP].op == ARP_OP_REPLY:
				self.handleArpReply(pkt)
		elif Pwospf in pkt:
			self.handlePwospf(pkt)
		elif IP in pkt:
			self.handleMissingIP(pkt)


	def send(self, *args, **override_kwargs):
		pkt = args[0]
		assert CPUMetadata in pkt, "Controller must send packets with special header"
		pkt[CPUMetadata].fromCpu = 1
		kwargs = dict(iface=self.iface, verbose=False)
		kwargs.update(override_kwargs)
		sendp(*args, **kwargs)

	def run(self):
		# Start up each hello pkt sender
		#for i in range(0, MAX_INTF): # Start up hello senders for each port except 1
		#	if(i == 0):
		#		continue
		#	else:
		#		self._helloSenderList[i].start()
		self.pwospfIntf.startIntfSenders() 
		sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

	def start(self, *args, **kwargs):
		super(MacLearningController, self).start(*args, **kwargs)
		time.sleep(self.start_wait)

	def join(self, *args, **kwargs):
		#for i in range(len(self._helloSenderList)):
			#if(self._helloSenderList[i]):	
				#self._helloSenderList[i].join(*args, **kwargs)
		self.stop_event.set()
		super(MacLearningController, self).join(*args, **kwargs)
