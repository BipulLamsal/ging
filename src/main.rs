use etherparse::err::packet;
use etherparse::{Ipv4Header, Ipv4HeaderSlice, Ipv4Slice, Ipv6Header};
use std::io::Write;
use std::str::MatchIndices;
use std::u16;
use tun_tap::Iface;
use tun_tap::Mode::Tun;
// Protocol 1 is for ICMP and protocol 6 for TCP and protocol 17 is for UDP

/*
 *  ICMP message are sent via basic IP header
 *  IH fields are
 *  version : 4 or 6
 *  IHL(header length) : 32 bit
 *  Identification, Flags, Fragment Offset
 *  protocol : 1 for ICMP
 *  see rfc 792
 *
 * */

pub struct Connection<'a> {
    ip: Ipv4Header,
    icmp_id: u16, //identifier
    seq_no: u16,  //sequence
    data: &'a [u8],
}
impl<'a> Connection<'a> {
    pub fn start(
        iph: Ipv4HeaderSlice,
        data: &'a [u8],
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        // ipv4 response packet
        let ip = Ipv4Header::new(
            0,
            64,
            etherparse::IpNumber(1),
            iph.destination(),
            iph.source(),
        )?;
        let identifier = u16::from_be_bytes(data[4..6].try_into()?);
        let seq_no = u16::from_be_bytes(data[6..8].try_into().unwrap());

        let c = Connection {
            ip,
            icmp_id: identifier,
            seq_no,
            data,
        };
        Ok(Some(c))
    }
    pub fn respond(&mut self, nic: &mut Iface) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = [0u8; 1500];

        //eth header
        let mut eth_header = [0u8; 14];
        eth_header[0..6].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);
        eth_header[6..12].copy_from_slice(&[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);
        eth_header[12..14].copy_from_slice(&[0x08, 0x00]); //represents ipv4 protocol

        //ipheader has 20 bytes
        let mut ip_header = [0u8; 20];
        ip_header[0] = 0x45; // header lenght which is 20
        ip_header[1] = 0x00; // ecn capable transport (default)
                             // ip_header[2..3] = self.ip.header_len() + self.ip.payload_len();
                             // added later on
        ip_header[4] = 0x00;
        ip_header[5] = 0x00;
        // fragmentation Offset
        ip_header[6] = 0x40; // dont fragment
        ip_header[7] = 0x00;

        //tll
        ip_header[8] = self.ip.time_to_live;
        ip_header[9] = self.ip.protocol.into();

        //checksum
        ip_header[10] = 0x00;
        ip_header[11] = 0x00;

        //source_addr
        ip_header[12..16].copy_from_slice(&self.ip.source);
        //desination_addr
        ip_header[16..20].copy_from_slice(&self.ip.destination[0..4]);
        // end of ip header

        //start of icmp packet strcture
        let mut icmp_packet = [0u8; 64];
        icmp_packet[0] = 0; // echo reply message
        icmp_packet[1] = 0; // code is zero for echo

        // checksum is 16 bit which is  8+8 from 2..ipv4
        icmp_packet[2] = 0;
        icmp_packet[3] = 0;

        icmp_packet[4] = (self.icmp_id >> 8) as u8; //high byte
        icmp_packet[5] = (self.icmp_id & 0xFF) as u8; //low byte masking with 255

        icmp_packet[6] = (self.seq_no >> 8) as u8;
        icmp_packet[7] = (self.seq_no & 0xFF) as u8;

        let total_ip_header_len = (ip_header[..].len() + icmp_packet[..].len()) as u16;
        ip_header[3] = (total_ip_header_len >> 8) as u8;
        ip_header[2] = total_ip_header_len as u8;

        //rest of the data
        icmp_packet[8..64].clone_from_slice(&self.data[8..64]);
        let sum = etherparse::checksum::Sum16BitWords::new();
        let iph_checksum = sum.add_slice(&ip_header[..]);
        let iph_checksum = iph_checksum.ones_complement();

        ip_header[10] = (iph_checksum >> 8) as u8;
        ip_header[11] = (iph_checksum & 0xff) as u8;

        calculate_checksum(&mut icmp_packet);

        // buf[..eth_header.len()].copy_from_slice(&eth_header);
        buf[..ip_header.len()].copy_from_slice(&ip_header);
        buf[ip_header.len()..ip_header.len() + icmp_packet.len()].copy_from_slice(&icmp_packet);
        let frame_length = ip_header.len() + icmp_packet.len();

        nic.send(&buf[..frame_length])?;
        Ok(())
    }
}

fn calculate_checksum(data: &mut [u8]) {
    let mut sum = 0u32;
    let mut i = 0;

    // Sum all 16-bit words
    while i < data.len() - 1 {
        let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
        sum = sum.wrapping_add(word);
        i += 2;
    }

    // If there's a byte left (odd number of bytes), pad it with zero
    if i < data.len() {
        let word = (data[i] as u32) << 8;
        sum = sum.wrapping_add(word);
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    // Calculate the one's complement of the sum
    let checksum = !(sum as u16);

    // Insert the checksum into the data at bytes 2 and 3
    data[2] = (checksum >> 8) as u8;
    data[3] = (checksum & 0xff) as u8;
}

#[allow(dead_code)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut nic = Iface::without_packet_info("tun0", Tun)?;
    let mut buf = [0u8; 1500]; // for iface without packet info the MTU is 1500 cap
    loop {
        // u16 captures 4 bits hex value
        let recv_packets = nic.recv(&mut buf[..])?;
        // let eth_flag = u16::from_be_bytes([buf[0], buf[1]]);
        // let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        // println!("ip flag: {:x}, ip protocol: {:x}", eth_flag, eth_proto);
        //skipping if it is not ipv4
        // if eth_proto != 0x0800 {
        //     continue;
        // }

        if let Some(iph) = Ipv4HeaderSlice::from_slice(&buf[..recv_packets]).ok() {
            let scr_addr = iph.source_addr();
            let dest_addr = iph.destination_addr();
            let protocol = iph.protocol();

            //skipping if it is not icmp header
            if protocol != etherparse::IpNumber(1) {
                continue;
            }
            println!(
                "src: {:?} -> des:{:?}, protocol: {:?}",
                scr_addr, dest_addr, protocol
            );
            // println!("packets: {:?}", iph);
            let data_buf = &buf[iph.slice().len()..recv_packets];
            // println!("packets: {:?}", data_buf);
            if let Some(mut connection) = Connection::start(iph, data_buf)? {
                connection.respond(&mut nic)?;
                println!("responded to type #{:?} packet from {}", protocol, scr_addr)
            }
        }
        // println!("Router Solitification or IPv6 received (ignoring them)")
    }
}
