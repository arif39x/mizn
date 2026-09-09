use bytemuck::{Pod, Zeroable};

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
#[cfg_attr(feature = "std", derive(Debug, Hash))]
pub struct FlowKey {
    pub source_ip: [u8; 16],
    pub destination_ip: [u8; 16],
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: u8,
    pub _alignment_padding: [u8; 3],
}

#[cfg(feature = "std")]
unsafe impl aya::Pod for FlowKey {}

#[repr(C, align(8))]
#[derive(Clone, Copy, PartialEq, Eq, Pod, Zeroable)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct FlowMetrics {
    pub bytes: u64,
    pub packets: u64,
    pub tcp_flags: u8,
    pub _explicit_padding_0: u8,
    pub _explicit_padding_1: u16,
    pub _explicit_padding_2: u32,
    pub sni: [u8; 64],
}

#[cfg(feature = "std")]
unsafe impl aya::Pod for FlowMetrics {}

impl Default for FlowMetrics {
    #[inline(always)]
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

