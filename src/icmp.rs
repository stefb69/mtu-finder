//! Platform ICMP backends for MTU probing.
//!
//! Each probe sends one ICMP echo request whose total IPv4 packet size
//! (20-byte IP header + 8-byte ICMP header + payload) equals the candidate
//! MTU, with do-not-fragment enabled, and classifies the outcome:
//!
//! * [`ProbeOutcome::Fits`] — a matching echo reply was received.
//! * [`ProbeOutcome::TooLarge`] — the kernel refused to send the packet
//!   (it is larger than the interface MTU with DF set). A *path* MTU
//!   violation is not visible to the application: the packet is sent, the
//!   first router drops it, so it surfaces as [`ProbeOutcome::Inconclusive`].
//! * [`ProbeOutcome::Inconclusive`] — no reply after all attempts. Ambiguous
//!   by design: it can mean oversized-and-dropped, ICMP filtering, packet
//!   loss, or an unreachable destination. Callers must not treat a timeout
//!   as a definitive "too large".
//! * [`ProbeOutcome::Fatal`] — a backend error unrelated to packet size.
//!
//! Do-not-fragment is platform specific and is configured accordingly:
//! * Linux:  `IP_MTU_DISCOVER = IP_PMTUDISC_DO`
//! * macOS:  `IP_DONTFRAG` (value 28, level `IPPROTO_IP`)
//! * FreeBSD: `IP_DONTFRAG`
//! * Windows: delegated to `ping-rs`, which sets the DF flag through
//!   `IcmpSendEchoWithOptions`.

use std::net::Ipv4Addr;
use std::time::Duration;

/// Smallest testable MTU: 20-byte IPv4 header + 8-byte ICMP echo header.
/// MTU candidates below this would need a negative payload size.
pub const MIN_MTU: u16 = 28;

/// Timeout applied to a single send/receive attempt within one probe.
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

/// Number of attempts per probe before the outcome is classified. Retries
/// reduce (but do not remove) the ambiguity of timeouts.
const PROBE_ATTEMPTS: u8 = 3;

/// Used by the Unix backend (which builds the ICMP header by hand) and by
/// the tests; ping-rs builds the header on Windows.
#[cfg(any(unix, test))]
const ICMP_ECHO_REQUEST: u8 = 8;
#[cfg(any(unix, test))]
#[allow(dead_code)] // unused in the Windows binary build (ping-rs builds the header)
const ICMP_ECHO_REPLY: u8 = 0;
#[cfg(any(unix, test))]
#[allow(dead_code)] // unused in the Windows binary build
const ICMP_HEADER_LEN: usize = 8;

/// Classified outcome of a single MTU probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// A matching echo reply was received: the size fits the path.
    Fits,
    /// The kernel definitively refused to send the packet (it exceeds the
    /// interface MTU with do-not-fragment enabled). Only produced by the
    /// Unix backend: the Windows API reports such failures as errors and
    /// ping-rs has no interface-MTU signal.
    #[allow(dead_code)]
    TooLarge,
    /// No reply after all attempts: ambiguous (filtered ICMP, loss, or a
    /// silently dropped oversized packet).
    Inconclusive,
    /// A backend error unrelated to packet size (socket failure, ...).
    Fatal(String),
}

/// An ICMP echo prober. Implementations own their socket state; all probes
/// target IPv4.
pub trait Pinger {
    /// Probe `mtu` (total IPv4 packet size in bytes, headers included).
    /// The implementation performs its own retries per
    /// [`PROBE_ATTEMPTS`].
    fn probe(&mut self, dst: Ipv4Addr, mtu: u16) -> ProbeOutcome;
}

/// Create the platform-appropriate pinger.
pub fn create_pinger() -> Result<Box<dyn Pinger>, String> {
    #[cfg(windows)]
    {
        Ok(Box::new(windows::WindowsPinger::new()))
    }
    #[cfg(unix)]
    {
        let pinger = unix::UnixPinger::new().map_err(|e| e.to_string())?;
        Ok(Box::new(pinger))
    }
}

/// ICMP one's-complement checksum (RFC 1071). Only used by the Unix
/// backend, which builds the ICMP header by hand; ping-rs builds it on
/// Windows.
#[cfg(any(unix, test))]
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += ((data[i] as u16) as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    // One's complement (NOT two's complement — wrapping_neg would be off by one).
    !(sum as u16)
}

#[cfg(unix)]
mod unix {
    use super::{icmp_checksum, *};
    use rand::Rng;
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    use std::io;
    use std::os::fd::AsRawFd;
    use std::net::{SocketAddr, SocketAddrV4};

    pub struct UnixPinger {
        sock: Socket,
        ident: u16,
        seq: u16,
    }

    impl UnixPinger {
        pub fn new() -> io::Result<Self> {
            // SOCK_DGRAM ICMP sockets do not require root.
            let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
            configure_dont_fragment(&sock)?;
            sock.set_read_timeout(Some(PROBE_TIMEOUT))?;
            Ok(Self {
                sock,
                ident: std::process::id() as u16,
                seq: 0,
            })
        }
    }

    /// Set the platform-specific do-not-fragment option.
    fn configure_dont_fragment(sock: &Socket) -> io::Result<()> {
        let fd = sock.as_raw_fd();
        unsafe {
            #[cfg(target_os = "linux")]
            {
                let val: libc::c_int = libc::IP_PMTUDISC_DO;
                check(libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_MTU_DISCOVER,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as u32,
                ))?;
            }
            #[cfg(target_os = "macos")]
            {
                // Darwin's IPv4 do-not-fragment option is IP_DONTFRAG at level
                // IPPROTO_IP (value 28 in netinet/in.h; not exposed by `libc`
                // for this target). Verified with setsockopt(2) on
                // SOCK_DGRAM/ICMP: IP_DONTFRAG succeeds, IPV6_DONTFRAG does not.
                let val: libc::c_int = 28;
                check(libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    val,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as u32,
                ))?;
            }
            #[cfg(target_os = "freebsd")]
            {
                let val: libc::c_int = 1;
                check(libc::setsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_DONTFRAG,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as u32,
                ))?;
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
            {
                // No DF option available on this platform: probes still work
                // but fragmentation may invalidate "fits" results.
                let _ = fd;
            }
        }
        Ok(())
    }

    fn check(res: libc::c_int) -> io::Result<()> {
        if res < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn is_timeout(err: &io::Error) -> bool {
        err.kind() == io::ErrorKind::WouldBlock
    }

    fn is_too_large(err: &io::Error) -> bool {
        // EMSGSIZE: kernel refused to send an unfragmentable oversized packet.
        // E2BIG: "argument list too long", returned by some kernels instead.
        matches!(
            err.raw_os_error(),
            Some(libc::EMSGSIZE) | Some(libc::E2BIG)
        )
    }

    impl Pinger for UnixPinger {
        fn probe(&mut self, dst: Ipv4Addr, mtu: u16) -> ProbeOutcome {
            debug_assert!(mtu >= MIN_MTU, "mtu below the IPv4+ICMP floor");
            let payload_len = mtu as usize - MIN_MTU as usize;

            // Build the ICMP echo request: the kernel adds the IPv4 header,
            // so wire size = payload_len + ICMP_HEADER_LEN + 20 = mtu.
            let mut pkt = vec![0u8; ICMP_HEADER_LEN + payload_len];
            pkt[0] = ICMP_ECHO_REQUEST;
            pkt[1] = 0;
            self.seq = self.seq.wrapping_add(1);
            pkt[4] = (self.ident >> 8) as u8;
            pkt[5] = (self.ident & 0xFF) as u8;
            pkt[6] = (self.seq >> 8) as u8;
            pkt[7] = (self.seq & 0xFF) as u8;
            // Random payload: defeats naive middlebox content filters.
            // Must be filled *before* the checksum is computed.
            rand::thread_rng().fill(&mut pkt[ICMP_HEADER_LEN..]);
            let csum = icmp_checksum(&pkt);
            pkt[2] = (csum >> 8) as u8;
            pkt[3] = csum as u8;

            // Room for the reply, which on macOS includes the 20-byte IPv4
            // header (wire size = mtu, so mtu + 64 covers any kernel padding).
            let mut raw = vec![std::mem::MaybeUninit::<u8>::uninit(); mtu as usize + 64];
            let target: SockAddr = SocketAddr::V4(SocketAddrV4::new(dst, 0)).into();
            for _ in 0..PROBE_ATTEMPTS {
                match self.sock.send_to(&pkt, &target) {
                    Ok(_) => match self.sock.recv_from(&mut raw) {
                        Ok((n, _)) if n >= ICMP_HEADER_LEN => {
                            let reply: Vec<u8> = raw[..n]
                                .iter()
                                .map(|b| unsafe { b.assume_init_read() })
                                .collect();
                            // macOS delivers the full IPv4 datagram (IP
                            // header included); Linux SOCK_DGRAM/ICMP strips
                            // it. An echo reply always starts with type
                            // 0x00, so a leading 0x45 is unambiguously an IP
                            // header.
                            let off = if reply[0] >> 4 == 4 && n >= ICMP_HEADER_LEN + 20 {
                                // IHL is the low nibble of the FIRST byte (0x45),
                                // not the TOS byte.
                                let ihl = (reply[0] & 0x0F) as usize;
                                if ihl < 5 { continue } else { ihl * 4 }
                            } else {
                                0
                            };
                            if off + ICMP_HEADER_LEN <= n
                                && reply[off] == ICMP_ECHO_REPLY
                                && u16::from_be_bytes([reply[off + 4], reply[off + 5]]) == self.ident
                                && u16::from_be_bytes([reply[off + 6], reply[off + 7]]) == self.seq
                            {
                                return ProbeOutcome::Fits;
                            }
                            // A datagram that is not our reply (e.g. an ICMP
                            // error addressed to us): ignore and retry.
                            continue;
                        }
                        // A datagram too short to be our echo reply: retry.
                        Ok(_) => continue,
                        Err(e) if is_timeout(&e) => continue,
                        Err(e) => return ProbeOutcome::Fatal(format!("recv failed: {e}")),
                    },
                    Err(e) if is_too_large(&e) => return ProbeOutcome::TooLarge,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return ProbeOutcome::Fatal(format!("send failed: {e}")),
                }
            }
            ProbeOutcome::Inconclusive
        }
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use rand::Rng;
    use std::net::IpAddr;

    pub struct WindowsPinger {
        payload: Vec<u8>,
    }

    impl WindowsPinger {
        pub fn new() -> Self {
            Self {
                payload: Vec::new(),
            }
        }
    }

    impl Pinger for WindowsPinger {
        fn probe(&mut self, dst: Ipv4Addr, mtu: u16) -> ProbeOutcome {
            debug_assert!(mtu >= MIN_MTU, "mtu below the IPv4+ICMP floor");
            let payload_len = mtu as usize - MIN_MTU as usize;
            self.payload.clear();
            self.payload.resize(payload_len, 0);
            rand::thread_rng().fill(&mut self.payload[..]);
            // ping-rs sends a bare payload (no pre-built ICMP header); the
            // Windows API adds the 8-byte ICMP header, so wire size
            // = payload_len + 8 + 20 = mtu. The `dont_fragment` option is
            // what makes oversized packets fail instead of fragmenting.
            let options = ping_rs::PingOptions {
                ttl: 128,
                dont_fragment: true,
            };
            for _ in 0..PROBE_ATTEMPTS {
                match ping_rs::send_ping(&IpAddr::V4(dst), PROBE_TIMEOUT, &self.payload, Some(&options))
                {
                    Ok(_) => return ProbeOutcome::Fits,
                    Err(ping_rs::PingError::TimedOut) => continue,
                    Err(e) => return ProbeOutcome::Fatal(format!("ping failed: {}", ping_error_desc(&e))),
                }
            }
            ProbeOutcome::Inconclusive
        }
    }

    /// ping-rs's `PingError` only derives `Debug`; render it readably.
    fn ping_error_desc(e: &ping_rs::PingError) -> String {
        match e {
            ping_rs::PingError::BadParameter(p) => format!("bad parameter: {p}"),
            ping_rs::PingError::OsError(code, msg) => format!("OS error {code}: {msg}"),
            ping_rs::PingError::IpError(status) => format!("ICMP error: {status:?}"),
            ping_rs::PingError::TimedOut => "timed out".into(),
            ping_rs::PingError::IoPending => "I/O pending".into(),
            ping_rs::PingError::DataSizeTooBig(max) => format!("payload larger than {max}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fold the one's-complement sum of `data` (which must include the
    /// checksum field) — a valid checksum folds to 0xFFFF.
    fn folded_sum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for chunk in data.chunks(2) {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum >> 16) + (sum & 0xFFFF);
        }
        (sum & 0xFFFF) as u16
    }

    #[test]
    fn checksum_folds_to_zero() {
        let mut pkt = vec![0u8; 64];
        pkt[0] = ICMP_ECHO_REQUEST;
        pkt[4] = 0xAB;
        pkt[5] = 0xCD;
        let csum = icmp_checksum(&pkt);
        pkt[2] = (csum >> 8) as u8;
        pkt[3] = csum as u8;
        assert_eq!(folded_sum(&pkt), 0xFFFF);
    }

    #[test]
    fn checksum_depends_on_payload() {
        let mut a = vec![0u8; 32];
        let mut b = vec![0u8; 32];
        a[0] = ICMP_ECHO_REQUEST;
        b[0] = ICMP_ECHO_REQUEST;
        b[10] = 1;
        assert_ne!(icmp_checksum(&a), icmp_checksum(&b));
    }

    #[test]
    #[ignore = "requires network access to 8.8.8.8 and a reachable route"]
    fn smoke_real_network() {
        let mut pinger = create_pinger().expect("pinger should be created");
        // 68 bytes is the classic default ping packet size; it must fit.
        assert_eq!(pinger.probe(Ipv4Addr::new(8, 8, 8, 8), 68), ProbeOutcome::Fits);
    }
}
