use aya_ebpf::{bindings::xdp_action, programs::XdpContext};
use core::mem;
use crate::headers::EthernetHeader;
use crate::parsing::ipv4::parse_ipv4;
use crate::parsing::ipv6::parse_ipv6;

pub mod ipv4;
pub mod ipv6;
pub mod transport;

pub const PROTO_ICMP:   u8 = 1;
pub const PROTO_TCP:    u8 = 6;
pub const PROTO_UDP:    u8 = 17;
pub const PROTO_GRE:    u8 = 47;
pub const PROTO_ICMP6:  u8 = 58;

pub const ETH_IPV4:     u16 = 0x0800;
pub const ETH_IPV6:     u16 = 0x86DD;

pub const PORT_VXLAN:   u16 = 4789;
pub const PORT_DNS:     u16 = 53;
pub const PORT_HTTP:    u16 = 80;

#[inline(always)]
pub unsafe fn make_flow_key(
    source_ip: [u8; 16],
    destination_ip: [u8; 16],
    source_port: u16,
    destination_port: u16,
    protocol: u8,
) -> mizn_common::bpf::FlowKey {
    let mut value = core::mem::MaybeUninit::<mizn_common::bpf::FlowKey>::uninit();
    let ptr = value.as_mut_ptr();
    unsafe {
        (*ptr).source_ip = source_ip;
        (*ptr).destination_ip = destination_ip;
        (*ptr).source_port = source_port;
        (*ptr).destination_port = destination_port;
        (*ptr).protocol = protocol;
        (*ptr)._alignment_padding[0] = 0;
        (*ptr)._alignment_padding[1] = 0;
        (*ptr)._alignment_padding[2] = 0;
        value.assume_init()
    }
}

#[inline(always)]
pub fn ipv4_to_v6_mapped(ip: u32) -> [u8; 16] {
    let b = ip.to_be_bytes();
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, b[0], b[1], b[2], b[3]]
}

#[inline(always)]
pub unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data() as *const u8;
    let end   = ctx.data_end() as *const u8;
    let ptr   = unsafe { start.add(offset) } as *const T;
    if unsafe { (ptr as *const u8).add(mem::size_of::<T>()) } > end {
        return Err(());
    }
    Ok(ptr)
}

#[inline(always)]
pub fn process_packet(ctx: &XdpContext) -> Result<u32, ()> {
    unsafe {
        let eth: *const EthernetHeader = ptr_at(ctx, 0)?;
        let ether_type = u16::from_be((*eth).ether_type);
        let after_eth = mem::size_of::<EthernetHeader>();

        match ether_type {
            ETH_IPV4 => parse_ipv4(ctx, after_eth, 0),
            ETH_IPV6 => parse_ipv6(ctx, after_eth, 0),
            _        => Ok(xdp_action::XDP_PASS),
        }
    }
}
