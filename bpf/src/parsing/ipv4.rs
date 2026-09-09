use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use mizn_common::bpf::FlowKey;
use crate::headers::{IcmpHeader, Ipv4Header};
use crate::maps::BLOCKLIST;
use crate::metrics::update_metrics;
use crate::parsing::{make_flow_key, ptr_at, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use crate::parsing::transport::{handle_transport_v4, TransportArgs};

#[inline(always)]
pub unsafe fn parse_ipv4(ctx: &XdpContext, ip_offset: usize, depth: u8) -> Result<u32, ()> {
    // Only support 1 level of encapsulation to save verifier permutations
    if depth > 0 { return Ok(xdp_action::XDP_PASS); }

    let ip: *const Ipv4Header = ptr_at(ctx, ip_offset)?;

    if BLOCKLIST.get(&(*ip).source_address).is_some()
        || BLOCKLIST.get(&(*ip).destination_address).is_some()
    {
        return Ok(xdp_action::XDP_DROP);
    }

    let protocol    = (*ip).protocol;
    let ihl         = (((*ip).version_ihl & 0x0F) as usize) << 2;
    let xport_off   = ip_offset + ihl;
    let src_ip      = crate::parsing::ipv4_to_v6_mapped((*ip).source_address);
    let dst_ip      = crate::parsing::ipv4_to_v6_mapped((*ip).destination_address);
    let pkt_len     = (ctx.data_end() - ctx.data()) as u64;

    match protocol {
        PROTO_TCP | PROTO_UDP => handle_transport_v4(ctx, &TransportArgs {
            xport_off, protocol, src_ip, dst_ip, pkt_len
        }),
        PROTO_ICMP => {
            let icmp: *const IcmpHeader = ptr_at(ctx, xport_off)?;
            let key = make_flow_key(src_ip, dst_ip, (*icmp).icmp_type as u16,
                (*icmp).code as u16, PROTO_ICMP);
            update_metrics(&key, pkt_len, 0);
            Ok(xdp_action::XDP_PASS)
        }
        // GRE encapsulation parsing removed to save BPF verification instructions
        _ => Ok(xdp_action::XDP_PASS),
    }
}
