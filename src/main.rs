fn main() {
    let interfaces = pnet::datalink::interfaces();
    let local_interfaces = interfaces.iter().flat_map(|itf| itf_local_addresses(&itf));

    let source_ip = get_source_ip();


    for (network, interface) in local_interfaces {
        check_endpoints(network, interface, source_ip);
    }
}

fn get_source_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
}

fn check_endpoints(network: IpNetwork, itf: &NetworkInterface, source_ip: IpAddr) {
    match network {
        IpNetwork::V4(n) => check_ipv4_network(n, itf, source_ip),
        IpNetwork::V6(n) => check_ipv6_network(n, itf, source_ip),
    }
}

use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::EthernetPacket;

// for whatever reason whenever we go below 1ms we can no longer get a hit.
const TIMEOUT_DUR: Option<Duration> = Some(Duration::from_micros(1000));

const ETH_PKT_SIZE: usize = EthernetPacket::minimum_packet_size();
const ARP_PKT_SIZE: usize = ArpPacket::minimum_packet_size();
const ARP_PKT_OFFSET: usize = ETH_PKT_SIZE;
fn check_ipv4_network(network: Ipv4Network, itf: &NetworkInterface, source_ip: IpAddr) {
    let source_ip = match source_ip {
        IpAddr::V4(ip) => ip,
        _ => unreachable!(),
    };

    let mac = itf.mac.unwrap();

    let mut pkt_buf = [0u8; ETH_PKT_SIZE + ARP_PKT_SIZE];
    let (mut send, mut recv) = build_eth_channel(itf);

    let start = Instant::now();
    let mut cnt = 0;

    //FIXME: do we really need to be sending a broadcast packet to every address?
    // we already iterate over all of the receiving packets in [wait_for_arp_resp]
    for dest_ip in network.iter() {
        write_ipv4_pkt(&mut pkt_buf, mac, source_ip, dest_ip);
        send.send_to(&pkt_buf, None).unwrap().unwrap();

        match wait_for_arp_resp(&mut recv, TIMEOUT_DUR, dest_ip, mac) {
            Ok((_dur, ip)) => {
                println!("hit {ip} !");
                cnt += 1;
            }
            Err(_e) => {
                //uh oh...
            }
        }
        pkt_buf.fill(0);
    }

    println!("found {cnt} running ips out of {} at {network} in {:?}", network.size(), start.elapsed());
}

fn write_ipv4_pkt(buf: &mut [u8], mac: MacAddr, source_ip: Ipv4Addr, dest_ip: Ipv4Addr) {
    write_ethernet_packet(buf, mac, EtherTypes::Arp);
    write_arp_packet(buf, mac, source_ip, dest_ip);
}

type DynErr = Box<dyn std::error::Error>;

use std::time::{Duration, Instant};

fn wait_for_arp_resp(
    recv: &mut Box<dyn DataLinkReceiver>,
    duration: Option<Duration>,
    target_ip: Ipv4Addr,
    mac: MacAddr,
) -> Result<(Duration, Ipv4Addr), DynErr> {
    let start = Instant::now();
    let max_dur = duration.unwrap_or_default();

    loop {
        let buf = recv.next()?;

        const ARP_PKT_MIN_RESP_SIZE: usize = ETH_PKT_SIZE + ARP_PKT_SIZE;

        if buf.len() < ARP_PKT_MIN_RESP_SIZE {
            check_timeout(&start, &max_dur)?;
            continue;
        }
        let arp_pkt = ArpPacket::new(&buf[ARP_PKT_OFFSET..]).unwrap();


        if arp_pkt.get_sender_proto_addr() == target_ip && arp_pkt.get_target_hw_addr() == mac {
            return Ok((start.elapsed(), arp_pkt.get_sender_proto_addr()));
        }

        check_timeout(&start, &max_dur)?;
    }
}

fn check_timeout(then: &Instant, dur: &Duration) -> Result<(), DynErr> {
    if then.elapsed() > *dur {
        Err("timeout".into())
    } else {
        Ok(())
    }
}

use pnet::datalink::Channel;
use pnet::datalink::{DataLinkReceiver, DataLinkSender};

fn build_eth_channel(
    itf: &NetworkInterface,
) -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>) {
    let mut link_cfg = pnet::datalink::Config::default();

    link_cfg.read_timeout = TIMEOUT_DUR;
    link_cfg.write_buffer_size = ETH_PKT_SIZE + ARP_PKT_SIZE;
    link_cfg.read_buffer_size = ETH_PKT_SIZE + ARP_PKT_SIZE;

    match pnet::datalink::channel(itf, link_cfg) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!(),
        //NOTE: this will always error unless ran in elevated privledges
        Err(e) => panic!("{e}"),
    }
}

use pnet::packet::ethernet::EtherType;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::MutableEthernetPacket;

fn write_ethernet_packet(buf: &mut [u8], mac: MacAddr, eth_type: EtherType) {
    let mut eth_pkt = MutableEthernetPacket::new(buf).unwrap();
    eth_pkt.set_destination(MacAddr::broadcast());
    eth_pkt.set_source(mac);
    eth_pkt.set_ethertype(eth_type);
}
use std::net::Ipv4Addr;

use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket};

fn write_arp_packet(buf: &mut [u8], mac: MacAddr, source_ip: Ipv4Addr, target_ip: Ipv4Addr) {
    let mut arp_pkt = MutableArpPacket::new(&mut buf[ARP_PKT_OFFSET..]).unwrap();

    arp_pkt.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_pkt.set_protocol_type(EtherTypes::Ipv4);
    arp_pkt.set_hw_addr_len(6);
    arp_pkt.set_proto_addr_len(4);
    arp_pkt.set_operation(ArpOperations::Request);
    arp_pkt.set_sender_hw_addr(mac);
    arp_pkt.set_sender_proto_addr(source_ip);
    arp_pkt.set_target_hw_addr(MacAddr::zero());
    arp_pkt.set_target_proto_addr(target_ip);
}

fn check_ipv6_network(_network: Ipv6Network, _itf: &NetworkInterface, _source_ip: IpAddr) {
    //FIXME: this can be done using ndp packets instead of arp
    //but its unlikely that well be using ipv6 so..
}

use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use pnet::datalink::NetworkInterface;

struct Network {
    inner: IpNetwork,
}

use std::net::IpAddr;

impl Network {
    fn new(inner: IpNetwork) -> Self {
        Self { inner }
    }

    fn map_local(self) -> Option<IpNetwork> {
        match &self.inner.network() {
            IpAddr::V4(ip) => {
                if ip.is_private() {
                    const FILTER_WLAN: bool = true;
                    if FILTER_WLAN && ip.octets()[0] == 10 {
                        return None;
                    }
                    return Some(self.inner);
                }
                None
            }
            IpAddr::V6(_network) => {
                //FIXME: add ipv6 support
                None
            }
        }
    }
}

use pnet::util::MacAddr;

fn itf_local_addresses(
    itf: &NetworkInterface,
) -> impl Iterator<Item = (IpNetwork, &NetworkInterface)> {
    itf.ips.iter().filter_map(move |network| {
        Network::new(*network)
            .map_local()
            .map(|network| (network, itf))
    })
}
