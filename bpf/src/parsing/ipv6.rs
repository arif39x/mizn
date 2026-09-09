use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use mizn_common::bpf::FlowKey;
use core::mem;
use crate::headers::{IcmpHeader, Ipv6Header};
use crate::maps::BLOCKLIST_V6;
use crate::metrics::update_metrics;
use crate::parsing::{make_flow_key, ptr_at, PROTO_ICMP6, PROTO_TCP, PROTO_UDP};
use crate::parsing::transport::{handle_transport_v4, TransportArgs};

#[inline(always)]
pub unsafe fn parse_ipv6(ctx: &XdpContext, ip_offset: usize, depth: u8) -> Result<u32, ()> {
    // Only support 1 level of encapsulation
    if depth > 0 { return Ok(xdp_action::XDP_PASS); }

    let ip6: *const Ipv6Header = ptr_at(ctx, ip_offset)?;

    if BLOCKLIST_V6.get(&(*ip6).source_address).is_some()
        || BLOCKLIST_V6.get(&(*ip6).destination_address).is_some()
    {
        return Ok(xdp_action::XDP_DROP);
    }

    let next    = (*ip6).next_header;
    let xport   = ip_offset + mem::size_of::<Ipv6Header>();
    let pkt_len = (ctx.data_end() - ctx.data()) as u64;

    let src_ip  = (*ip6).source_address;
    let dst_ip  = (*ip6).destination_address;

    match next {
        PROTO_TCP | PROTO_UDP => handle_transport_v4(ctx, &TransportArgs {
            xport_off: xport, protocol: next, src_ip, dst_ip, pkt_len
        }),
        PROTO_ICMP6 => {
            let icmp: *const IcmpHeader = ptr_at(ctx, xport)?;
            let key = make_flow_key(src_ip, dst_ip, (*icmp).icmp_type as u16,
                (*icmp).code as u16, PROTO_ICMP6);
            update_metrics(&key, pkt_len, 0);
            Ok(xdp_action::XDP_PASS)
        }
        _ => Ok(xdp_action::XDP_PASS),
    }
}
