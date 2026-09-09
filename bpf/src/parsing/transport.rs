use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use core::mem;
use mizn_common::bpf::FlowKey;
use crate::headers::{EthernetHeader, Ipv4Header, Ipv6Header, TcpHeader, UdpHeader, VxlanHeader};
use crate::maps::{BLOCKLIST, BLOCKLIST_V6};
use crate::metrics::update_metrics_with_sni;
use crate::parsing::{make_flow_key, ptr_at, PROTO_TCP, PROTO_UDP, ETH_IPV4, ETH_IPV6, PORT_VXLAN, PORT_DNS, PORT_HTTP};

pub struct TransportArgs {
    pub xport_off: usize,
    pub protocol: u8,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub pkt_len: u64,
}

#[inline(always)]
unsafe fn inner_ip_off_for_vxlan(ctx: &XdpContext, udp_off: usize) -> Option<(usize, u16)> {
    let inner_eth_off = udp_off + 8 + mem::size_of::<VxlanHeader>();
    let inner_eth: *const EthernetHeader = ptr_at(ctx, inner_eth_off).ok()?;
    let etype = u16::from_be((*inner_eth).ether_type);
    Some((inner_eth_off + mem::size_of::<EthernetHeader>(), etype))
}

#[inline(always)]
unsafe fn dispatch_flat(ctx: &XdpContext, ip_off: usize, etype: u16) -> Result<u32, ()> {
    match etype {
        ETH_IPV4 => {
            let ip: *const Ipv4Header = ptr_at(ctx, ip_off)?;
            if BLOCKLIST.get(&(*ip).source_address).is_some()
                || BLOCKLIST.get(&(*ip).destination_address).is_some()
            {
                return Ok(xdp_action::XDP_DROP);
            }
            let proto   = (*ip).protocol;
            let ihl     = (((*ip).version_ihl & 0x0F) as usize) << 2;
            let xoff    = ip_off + ihl;
            let pkt_len = (ctx.data_end() - ctx.data()) as u64;
            let src_ip  = crate::parsing::ipv4_to_v6_mapped((*ip).source_address);
            let dst_ip  = crate::parsing::ipv4_to_v6_mapped((*ip).destination_address);
            process_transport_flat(ctx, xoff, proto, src_ip, dst_ip, pkt_len)
        }
        ETH_IPV6 => {
            let ip6: *const Ipv6Header = ptr_at(ctx, ip_off)?;
            if BLOCKLIST_V6.get(&(*ip6).source_address).is_some()
                || BLOCKLIST_V6.get(&(*ip6).destination_address).is_some()
            {
                return Ok(xdp_action::XDP_DROP);
            }
            let proto   = (*ip6).next_header;
            let xoff    = ip_off + mem::size_of::<Ipv6Header>();
            let pkt_len = (ctx.data_end() - ctx.data()) as u64;
            process_transport_flat(ctx, xoff, proto, (*ip6).source_address, (*ip6).destination_address, pkt_len)
        }
        _ => Ok(xdp_action::XDP_PASS),
    }
}

#[inline(always)]
unsafe fn process_transport_flat(ctx: &XdpContext, xoff: usize, proto: u8, src_ip: [u8; 16], dst_ip: [u8; 16], pkt_len: u64) -> Result<u32, ()> {
    if proto != PROTO_TCP && proto != PROTO_UDP { return Ok(xdp_action::XDP_PASS); }
    let (sp, dp, payload_off, flags) = if proto == PROTO_TCP {
        let tcp: *const TcpHeader = ptr_at(ctx, xoff)?;
        let thlen = (((*tcp).data_offset_reserved >> 4) as usize) << 2;
        (u16::from_be((*tcp).source_port), u16::from_be((*tcp).destination_port), xoff + thlen, (*tcp).flags)
    } else {
        let udp: *const UdpHeader = ptr_at(ctx, xoff)?;
        (u16::from_be((*udp).source_port), u16::from_be((*udp).destination_port), xoff + 8, 0u8)
    };
    let key = make_flow_key(src_ip, dst_ip, sp, dp, proto);
    update_metrics_with_sni(ctx, &key, pkt_len, flags, proto, dp, payload_off);
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
pub unsafe fn handle_transport_v4(ctx: &XdpContext, args: &TransportArgs) -> Result<u32, ()> {
    let (src_port, dst_port, payload_off, flags) = if args.protocol == PROTO_TCP {
        let tcp: *const TcpHeader = ptr_at(ctx, args.xport_off)?;
        let thlen = (((*tcp).data_offset_reserved >> 4) as usize) << 2;
        (u16::from_be((*tcp).source_port), u16::from_be((*tcp).destination_port), args.xport_off + thlen, (*tcp).flags)
    } else {
        let udp: *const UdpHeader = ptr_at(ctx, args.xport_off)?;
        let sp = u16::from_be((*udp).source_port);
        let dp = u16::from_be((*udp).destination_port);
        if dp == PORT_VXLAN || sp == PORT_VXLAN {
            if let Some((inner_ip_off, etype)) = inner_ip_off_for_vxlan(ctx, args.xport_off) {
                return dispatch_flat(ctx, inner_ip_off, etype);
            }
            return Ok(xdp_action::XDP_PASS);
        }
        (sp, dp, args.xport_off + 8, 0u8)
    };
    let key = make_flow_key(args.src_ip, args.dst_ip, src_port, dst_port, args.protocol);
    update_metrics_with_sni(ctx, &key, args.pkt_len, flags, args.protocol, dst_port, payload_off);
    Ok(xdp_action::XDP_PASS)
}
