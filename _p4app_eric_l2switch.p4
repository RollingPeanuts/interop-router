/* -*- P4_16 -*- */
#include <core.p4> 
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t; 
const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<16> TYPE_IP		= 0x0800;
const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;

const bit<8>  TYPE_PWOSPF 	= 0x59;

header ethernet_t {
	macAddr_t dstAddr;
	macAddr_t srcAddr;
	bit<16>   etherType;
}

header cpu_metadata_t {
	bit<8> fromCpu;
	bit<16> origEtherType;
	bit<16> srcPort;
}

header ipv4_t {
	bit<4> version;
	bit<4> ihl;
	bit<8> diffserv;
	bit<16> totalLen;
	bit<16> identification;
	bit<3> flags;
	bit<13> fragOffset;
	bit<8> ttl;
	bit<8> protocol;
	bit<16> hdrChecksum;
	ip4Addr_t srcAddr;
	ip4Addr_t dstAddr;
}

header arp_t {
	bit<16> hwType;
	bit<16> protoType;
	bit<8> hwAddrLen;
	bit<8> protoAddrLen;
	bit<16> opcode;
	// assumes hardware type is ethernet and protocol is IP
	macAddr_t srcEth;
	ip4Addr_t srcIP;
	macAddr_t dstEth;
	ip4Addr_t dstIP;
}

header pwospf_t {
	bit<8> version;
	bit<8> type;
	bit<16> len;
	bit<32> routerId;
	bit<32> areaId;
	bit<16> checksum;
	bit<16> auType;
	bit<64> authentication;
}

struct headers {
	ethernet_t        ethernet;
	cpu_metadata_t    cpu_metadata;
	ipv4_t		ipv4;
	arp_t             arp;
	pwospf_t 	pwospf;
}

struct metadata { }

parser MyParser(packet_in packet,
		out headers hdr,
		inout metadata meta,
		inout standard_metadata_t standard_metadata) {
	state start {
		transition parse_ethernet;
	}

	state parse_ethernet {
		packet.extract(hdr.ethernet);
		transition select(hdr.ethernet.etherType) {
			TYPE_ARP: parse_arp;
			TYPE_CPU_METADATA: parse_cpu_metadata;
			TYPE_IP: parse_ip;
			default: accept;
		}
	}

	state parse_cpu_metadata {
		packet.extract(hdr.cpu_metadata);
		transition select(hdr.cpu_metadata.origEtherType) {
			TYPE_ARP: parse_arp;
			TYPE_IP:  parse_ip;
			default: accept;
		}
	}

	state parse_arp {
		packet.extract(hdr.arp);
		transition accept;
	}

	state parse_ip {
		packet.extract(hdr.ipv4);
		transition select(hdr.ipv4.protocol) {
			TYPE_PWOSPF: parse_pwospf;
			default: accept;
		}
	}

	state parse_pwospf {
		packet.extract(hdr.pwospf);
		transition accept;
	}
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
	apply { }
}

control MyIngress(inout headers hdr,
		inout metadata meta,
		inout standard_metadata_t standard_metadata) {
	/* Declarations */
	bit<32> tmpIP;
	bit<32> counterVal;
	register<bit<32>>(3) counterReg;

	action drop() {
		mark_to_drop();
	}

	action set_egr(port_t port) {
		standard_metadata.egress_spec = port;
	}

	action set_mgid(mcastGrp_t mgid) {
		standard_metadata.mcast_grp = mgid;
	}

	action cpu_meta_encap() {
		hdr.cpu_metadata.setValid();
		hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
		hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
		hdr.ethernet.etherType = TYPE_CPU_METADATA;
	}

	action cpu_meta_decap() {
		hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
		hdr.cpu_metadata.setInvalid();
	}

	action send_to_cpu() {
		cpu_meta_encap();
		standard_metadata.egress_spec = CPU_PORT;
	}

	action ipv4_fwd(macAddr_t mac, port_t port) {
		hdr.ethernet.dstAddr = mac;
		standard_metadata.egress_spec = port;
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;	
	}

	table fwd_l2 {
		key = {
			hdr.ethernet.dstAddr: exact;
		}
		actions = {
			set_egr;
			set_mgid;
			drop;
			NoAction;
		}
		size = 1024;
		default_action = NoAction();
	}

	table fwd_ip {
		key = {
			hdr.ipv4.dstAddr: lpm;
		}
		actions = {
			ipv4_fwd;
			send_to_cpu;
			drop;
			NoAction;
		}
		size = 1024;
		default_action = NoAction();
	}

	table local_fwd {
		key = {
			hdr.ipv4.srcAddr: exact;
		}
		actions = {
			set_egr;
			drop;
			NoAction;
		}
		size = 1024;
		default_action = NoAction();
	}

	action return_arp(macAddr_t cachedMac) {
		/* Flip ethernet hdr addresss and ports */
		hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
		hdr.ethernet.srcAddr = cachedMac;
		standard_metadata.egress_spec = standard_metadata.ingress_port;

		/* Flip arp header values */
		hdr.arp.opcode = 0x2;
		tmpIP = hdr.arp.srcIP;
		hdr.arp.srcIP = hdr.arp.dstIP;
		hdr.arp.dstIP = tmpIP;
		hdr.arp.dstEth = hdr.arp.srcEth;
		hdr.arp.srcEth = cachedMac;
	}


	table arp_cache {
		key = {
			hdr.arp.dstIP: exact;
		}
		actions = {
			return_arp;
			drop;
			NoAction;
		}
		size = 1024;
		default_action = NoAction();
	}


	apply {

		if (standard_metadata.ingress_port == CPU_PORT)
			cpu_meta_decap();

		/* TODO: Change the logic here */
		if(hdr.ipv4.isValid() && hdr.pwospf.isValid() && standard_metadata.ingress_port == CPU_PORT) {
			/* fwd_ip.apply(); */
			local_fwd.apply();	
		}
		else {
			if (hdr.arp.isValid() && standard_metadata.ingress_port != CPU_PORT) {
				counterReg.read(counterVal, 1);
				counterReg.write(0, counterVal + 1);
				if(hdr.arp.opcode == ARP_OP_REQ && !arp_cache.apply().hit) {
					counterReg.read(counterVal, 1);
					counterReg.write(1, counterVal + 1);
					send_to_cpu();
				}
				else if(hdr.arp.opcode == ARP_OP_REPLY) {
					counterReg.read(counterVal, 1);
					counterReg.write(1, counterVal + 1);
					send_to_cpu();
				}
			}
			else if (hdr.pwospf.isValid() && standard_metadata.ingress_port != CPU_PORT) {
				counterReg.read(counterVal, 1);
				counterReg.write(1, counterVal + 1);
				send_to_cpu();
			}
			else if(hdr.ipv4.isValid() && !hdr.arp.isValid()) {
				counterReg.read(counterVal, 2);
				counterReg.write(2, counterVal + 1);
				fwd_ip.apply();	
				fwd_l2.apply();
			}
			else if (hdr.ethernet.isValid()) {
				fwd_l2.apply();
			}
		}

	}
}

control MyEgress(inout headers hdr,
		inout metadata meta,
		inout standard_metadata_t standard_metadata) {
	apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
	apply {
        	update_checksum(
			hdr.ipv4.isValid(),
			{ hdr.ipv4.version,
			  hdr.ipv4.ihl,
			  hdr.ipv4.diffserv,
			  hdr.ipv4.totalLen,
			  hdr.ipv4.identification,
			  hdr.ipv4.flags,
			  hdr.ipv4.fragOffset,
			  hdr.ipv4.ttl,
			  hdr.ipv4.protocol,
			  hdr.ipv4.srcAddr,
			  hdr.ipv4.dstAddr },
			hdr.ipv4.hdrChecksum,
			HashAlgorithm.csum16);
	}
}

control MyDeparser(packet_out packet, in headers hdr) {
	apply {
		packet.emit(hdr.ethernet);
		packet.emit(hdr.cpu_metadata);
		packet.emit(hdr.arp);
		packet.emit(hdr.ipv4);
		packet.emit(hdr.pwospf);
	}
}

V1Switch(
	MyParser(),
	MyVerifyChecksum(),
	MyIngress(),
	MyEgress(),
	MyComputeChecksum(),
	MyDeparser()
) main;
