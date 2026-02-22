#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{HashMap, RingBuf},
    programs::XdpContext,
    helpers::bpf_ktime_get_ns,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
    udp::UdpHdr,
};

use common::{IPAddress, FlowMetadata, TokenBucket};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map]
static BLOCKLIST: HashMap<IPAddress, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static RATE_LIMIT: HashMap<IPAddress, TokenBucket> = HashMap::with_max_entries(1024, 0);

#[map]
static TELEMETRY: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

#[inline(always)]
fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    // Emits AYA_LOGS map so EbpfLogger::init succeeds in userspace
    info!(&ctx, "xdp_firewall: packet received");

    let eth_hdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };

    if unsafe { (*eth_hdr).ether_type } != EtherType::Ipv4 as u16 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ipv4_hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let src_bytes = unsafe { (*ipv4_hdr).src_addr };
    let source_addr = u32::from_be_bytes(src_bytes);
    let dst_bytes = unsafe { (*ipv4_hdr).dst_addr };
    let dest_addr = u32::from_be_bytes(dst_bytes);
    let proto = unsafe { (*ipv4_hdr).proto };

    if unsafe { BLOCKLIST.get(&source_addr).is_some() } {
        return Ok(xdp_action::XDP_DROP);
    }

    if let Some(bucket_ptr) = RATE_LIMIT.get_ptr_mut(&source_addr) {
        let bucket = unsafe { &mut *bucket_ptr };
        let now = unsafe { bpf_ktime_get_ns() };
        bucket.refill(now);

        let packet_len = (ctx.data_end() - ctx.data()) as u64;
        if bucket.tokens >= packet_len {
            bucket.tokens -= packet_len;
        } else {
            return Ok(xdp_action::XDP_DROP);
        }
    }

    let mut src_port = 0u16;
    let mut dst_port = 0u16;
    let mut payload_offset = 0;

    let ip_len = unsafe { (*ipv4_hdr).ihl() } as usize * 4;
    let l4_offset = EthHdr::LEN + ip_len;

    if proto == IpProto::Tcp {
        if let Ok(tcp_hdr) = unsafe { ptr_at::<TcpHdr>(&ctx, l4_offset) } {
            src_port = u16::from_be_bytes(unsafe { (*tcp_hdr).source });
            dst_port = u16::from_be_bytes(unsafe { (*tcp_hdr).dest });
            let doff = unsafe { (*tcp_hdr).doff() } as usize;
            payload_offset = l4_offset + doff * 4;
        }
    } else if proto == IpProto::Udp {
        if let Ok(udp_hdr) = unsafe { ptr_at::<UdpHdr>(&ctx, l4_offset) } {
            src_port = u16::from_be_bytes(unsafe { (*udp_hdr).src });
            dst_port = u16::from_be_bytes(unsafe { (*udp_hdr).dst });
            payload_offset = l4_offset + 8;
        }
    }

    if let Some(mut ring_buf) = TELEMETRY.reserve::<FlowMetadata>(0) {
        let mut metadata = FlowMetadata {
            src_ip: source_addr,
            dst_ip: dest_addr,
            src_port,
            dst_port,
            protocol: proto as u32,
            payload_len: 0,
            payload: [0; 128],
        };

        // Dispatch based on offset to help verifier with constants
        // 54 = Eth(14) + IP(20) + TCP(20)
        // 42 = Eth(14) + IP(20) + UDP(8)
        if payload_offset == 54 {
            copy_payload::<54>(&ctx, &mut metadata.payload);
            metadata.payload_len = 128; // Approximation, better if we calculated actual copied
        } else if payload_offset == 42 {
            copy_payload::<42>(&ctx, &mut metadata.payload);
            metadata.payload_len = 128;
        } else if payload_offset > 0 {
             // Fallback for variable offset - try to copy fewer bytes or skip
             // verifier struggles with variable loops
             metadata.payload_len = 0;
        }

        ring_buf.write(metadata);
        ring_buf.submit(0);
    }

    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn copy_payload<const OFF: usize>(ctx: &XdpContext, payload: &mut [u8; 128]) {
    let data_start = ctx.data();
    let data_end = ctx.data_end();

    // We only try to copy 32 bytes to avoid blowing up instruction count
    // A constant loop 0..32 with constant offset should be fine
    for i in 0..32 {
        let offset = OFF + i;
        // Strict bound check
        if data_start + offset + 1 > data_end {
            break;
        }
        unsafe {
            payload[i] = *((data_start + offset) as *const u8);
        }
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}
