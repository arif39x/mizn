use aya_ebpf::macros::map;
use aya_ebpf::maps::{HashMap, PerCpuHashMap};
use mizn_common::bpf::{FlowKey, FlowMetrics};

#[map]
pub static FLOW_METRICS: PerCpuHashMap<FlowKey, FlowMetrics> = PerCpuHashMap::with_max_entries(10240, 0);

#[map]
pub static BLOCKLIST: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[map]
pub static BLOCKLIST_V6: HashMap<[u8; 16], u8> = HashMap::with_max_entries(256, 0);


#[map]
pub static PORT_TO_PID: HashMap<u32, u32> = HashMap::with_max_entries(65536, 0);
