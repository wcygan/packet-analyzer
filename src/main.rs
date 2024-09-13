use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use std::env;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: sudo {} <network_interface>", args[0]);
        process::exit(1);
    }

    let interface_name = &args[1];
    let interface = find_network_interface(interface_name);
    let rx = create_datalink_channel(&interface, interface_name);

    println!(
        "Capturing packets on interface '{}'. Press Ctrl+C to stop.",
        interface_name
    );

    let running = setup_ctrlc_handler();
    capture_packets(rx, running);
}

fn find_network_interface(interface_name: &str) -> datalink::NetworkInterface {
    let interfaces = datalink::interfaces();
    interfaces
        .into_iter()
        .find(|iface| iface.name == *interface_name)
        .unwrap_or_else(|| {
            eprintln!("Error: Network interface '{}' not found.", interface_name);
            process::exit(1);
        })
}

fn create_datalink_channel(
    interface: &datalink::NetworkInterface,
    interface_name: &str,
) -> Box<dyn datalink::DataLinkReceiver> {
    match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(_, rx)) => rx,
        Ok(_) => {
            eprintln!(
                "Error: Unsupported channel type for interface '{}'.",
                interface_name
            );
            process::exit(1);
        }
        Err(e) => {
            eprintln!(
                "Error: Failed to create datalink channel for '{}': {}",
                interface_name, e
            );
            process::exit(1);
        }
    }
}

fn setup_ctrlc_handler() -> Arc<AtomicBool> {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })
        .expect("Error setting Ctrl-C handler");
    running
}

fn capture_packets(
    mut rx: Box<dyn datalink::DataLinkReceiver>,
    running: Arc<AtomicBool>,
) {
    while running.load(Ordering::SeqCst) {
        match rx.next() {
            Ok(packet) => {
                handle_packet(packet);
            }
            Err(e) => {
                eprintln!("An error occurred while reading a packet: {}", e);
            }
        }
    }
    println!("\nTerminating packet capture.");
}

fn handle_packet(packet: &[u8]) {
    if let Some(ethernet) = EthernetPacket::new(packet) {
        print_ethernet_packet(&ethernet);
        if ethernet.get_ethertype() == pnet::packet::ethernet::EtherTypes::Ipv4 {
            if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                print_ipv4_packet(&ipv4);
            }
        }
    }
}

fn print_ethernet_packet(ethernet: &EthernetPacket) {
    println!(
        "Ethernet Packet: {} -> {} | Ethertype: {:?} | Length: {}",
        ethernet.get_source(),
        ethernet.get_destination(),
        ethernet.get_ethertype(),
        ethernet.packet().len()
    );
}

fn print_ipv4_packet(ipv4: &Ipv4Packet) {
    let src = ipv4.get_source();
    let dst = ipv4.get_destination();
    let protocol = ipv4.get_next_level_protocol();
    let ttl = ipv4.get_ttl();
    let checksum = ipv4.get_checksum();

    let protocol_str = match protocol {
        IpNextHeaderProtocols::Tcp => "TCP",
        IpNextHeaderProtocols::Udp => "UDP",
        IpNextHeaderProtocols::Icmp => "ICMP",
        other => {
            println!("Unsupported protocol: {:?}", other);
            return;
        }
    };

    println!(
        "IPv4 Packet: Source: {} -> Destination: {} | Protocol: {} | TTL: {} | Checksum: {}",
        src, dst, protocol_str, ttl, checksum
    );
}