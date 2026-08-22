//! MTU search over a monotonic predicate.
//!
//! For a fixed destination, "a packet of size S with DF set is answered" is
//! (approximately) monotonic: if S fits, everything smaller fits. The search
//! therefore:
//!
//! 1. **Preflight** — verifies that the *smallest* size fits. If even the
//!    minimum does not (or gets no reply), the tool reports an error instead
//!    of silently returning the minimum as if it were measured.
//! 2. **Binary search** between a known-good size and the (unverified) top of
//!    the range. `Inconclusive` outcomes are handled conservatively: a size
//!    that never answers is treated as *not fitting*, but the final report is
//!    flagged so the user knows the true MTU may be slightly higher.
//! 3. **Boundary confirmation** — re-probes the last verified size to make
//!    sure the reported MTU still fits.

use crate::icmp::{Pinger, ProbeOutcome, MIN_MTU};
use std::fmt;
use std::net::Ipv4Addr;

/// An inclusive MTU range, already validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtuRange {
    pub min: u16,
    pub max: u16,
}

impl MtuRange {
    /// Validate a user-supplied range.
    pub fn new(min: u16, max: u16) -> Result<Self, String> {
        if min < MIN_MTU {
            return Err(format!(
                "minimum MTU {min} is below the IPv4+ICMP overhead floor of {MIN_MTU} bytes"
            ));
        }
        if min > max {
            return Err(format!("inverted range: min {min} > max {max}"));
        }
        Ok(Self { min, max })
    }
}

/// UI updates emitted while searching.
pub trait ProgressReporter {
    /// A probe of `size` is about to be sent.
    fn probing(&mut self, size: u16);
    /// A probe of `size` finished with `outcome`.
    fn result(&mut self, size: u16, outcome: &ProbeOutcome);
    /// The search finished.
    fn finish(&mut self, message: &str);
}

/// Result of a successful search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    /// Largest size verified to fit (answered by the destination).
    pub mtu: u16,
    /// `true` when `mtu` equals the tested `max`: the true MTU may be higher,
    /// a wider `-r` range would be needed to say more.
    pub reached_range_max: bool,
    /// `true` when the boundary above `mtu` was inferred from timeouts
    /// rather than a definitive rejection: the true MTU may be slightly
    /// higher.
    pub upper_inconclusive: bool,
}

/// Why the search could not produce a result.
#[derive(Debug)]
pub enum FindError {
    /// Even the smallest size did not fit / got no reply. Nothing can be
    /// measured — reporting the minimum would be a lie.
    Unreachable { min: u16, detail: String },
    /// Backend failure unrelated to packet size.
    Fatal(String),
}

impl fmt::Display for FindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FindError::Unreachable { min, detail } => {
                write!(
                    f,
                    "no working MTU found (smallest size probed: {min} bytes): {detail}"
                )
            }
            FindError::Fatal(detail) => write!(f, "ICMP backend error: {detail}"),
        }
    }
}

impl std::error::Error for FindError {}

/// Search the largest MTU in `range` that fits the path to `dst`.
pub fn find_mtu(
    dst: Ipv4Addr,
    range: &MtuRange,
    pinger: &mut dyn Pinger,
    reporter: &mut dyn ProgressReporter,
) -> Result<ProbeReport, FindError> {
    let min = range.min;
    let max = range.max;

    // 1. Preflight: the minimum must actually work.
    reporter.probing(min);
    let outcome = pinger.probe(dst, min);
    reporter.result(min, &outcome);
    match outcome {
        ProbeOutcome::Fits => {}
        ProbeOutcome::TooLarge => {
            return Err(FindError::Unreachable {
                min,
                detail: "the smallest size was rejected as too large".into(),
            })
        }
        ProbeOutcome::Inconclusive => {
            return Err(FindError::Unreachable {
                min,
                detail: "no echo reply — destination down or ICMP filtered".into(),
            })
        }
        ProbeOutcome::Fatal(detail) => return Err(FindError::Fatal(detail)),
    }

    if min == max {
        return Ok(ProbeReport {
            mtu: min,
            reached_range_max: true,
            upper_inconclusive: false,
        });
    }

    // 2. Binary search.
    //    Invariant: `lo` is known to fit; `hi` is known not to fit
    //    (initially `max + 1`, never tested: `hi_inconclusive` tracks that).
    let mut lo = min as u32;
    let mut hi = max as u32 + 1;
    let mut hi_inconclusive = true;

    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        reporter.probing(mid as u16);
        let outcome = pinger.probe(dst, mid as u16);
        reporter.result(mid as u16, &outcome);
        match outcome {
            ProbeOutcome::Fits => lo = mid,
            ProbeOutcome::TooLarge => {
                hi = mid;
                hi_inconclusive = false;
            }
            // Conservative: an unverified size counts as not fitting, but the
            // report will say so.
            ProbeOutcome::Inconclusive => {
                hi = mid;
                hi_inconclusive = true;
            }
            ProbeOutcome::Fatal(detail) => return Err(FindError::Fatal(detail)),
        }
    }

    // 3. Boundary confirmation: re-verify that `lo` still fits.
    reporter.probing(lo as u16);
    let outcome = pinger.probe(dst, lo as u16);
    reporter.result(lo as u16, &outcome);
    if outcome != ProbeOutcome::Fits {
        return Err(FindError::Unreachable {
            min: lo as u16,
            detail: "boundary confirmation failed: the last verified size no longer fits".into(),
        });
    }

    Ok(ProbeReport {
        mtu: lo as u16,
        reached_range_max: lo == max as u32,
        upper_inconclusive: hi_inconclusive && lo < max as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic fake backend: sizes <= `threshold` fit (unless
    /// `min_replies` is false, simulating globally filtered ICMP), sizes
    /// above `threshold` are definitively rejected — or merely silent when
    /// `flaky` (simulating path-MTU drops that look like timeouts).
    struct FakePinger {
        threshold: u16,
        flaky: bool,
        min_replies: bool,
        fatal: Option<String>,
        probes: Vec<u16>,
    }

    impl FakePinger {
        fn new(threshold: u16) -> Self {
            Self {
                threshold,
                flaky: false,
                min_replies: true,
                fatal: None,
                probes: Vec::new(),
            }
        }
    }

    impl Pinger for FakePinger {
        fn probe(&mut self, _dst: Ipv4Addr, mtu: u16) -> ProbeOutcome {
            self.probes.push(mtu);
            if let Some(detail) = &self.fatal {
                return ProbeOutcome::Fatal(detail.clone());
            }
            if mtu <= self.threshold {
                if self.min_replies {
                    ProbeOutcome::Fits
                } else {
                    ProbeOutcome::Inconclusive
                }
            } else if self.flaky {
                ProbeOutcome::Inconclusive
            } else {
                ProbeOutcome::TooLarge
            }
        }
    }

    struct Noop;
    impl ProgressReporter for Noop {
        fn probing(&mut self, _size: u16) {}
        fn result(&mut self, _size: u16, _outcome: &ProbeOutcome) {}
        fn finish(&mut self, _message: &str) {}
    }

    fn range() -> MtuRange {
        MtuRange::new(1300, 1500).unwrap()
    }
    fn dst() -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, 1)
    }

    #[test]
    fn finds_exact_threshold() {
        let mut f = FakePinger::new(1450);
        let report = find_mtu(dst(), &range(), &mut f, &mut Noop).unwrap();
        assert_eq!(report.mtu, 1450);
        assert!(!report.reached_range_max);
        assert!(!report.upper_inconclusive);
        // 1 preflight + ~log2(201) steps + 1 confirmation.
        assert!(
            f.probes.len() <= 12,
            "too many probes for a binary search: {:?}",
            f.probes
        );
    }

    #[test]
    fn stops_at_range_max() {
        let mut f = FakePinger::new(1500);
        let report = find_mtu(dst(), &range(), &mut f, &mut Noop).unwrap();
        assert_eq!(report.mtu, 1500);
        assert!(report.reached_range_max);
        assert!(!report.upper_inconclusive);
    }

    #[test]
    fn threshold_at_min() {
        let mut f = FakePinger::new(1300);
        let report = find_mtu(dst(), &range(), &mut f, &mut Noop).unwrap();
        assert_eq!(report.mtu, 1300);
        assert!(!report.reached_range_max);
        assert!(!report.upper_inconclusive);
    }

    #[test]
    fn preflight_failure_is_an_error_not_a_measurement() {
        let mut f = FakePinger::new(1450);
        f.min_replies = false; // nothing ever gets a reply
        let err = find_mtu(dst(), &range(), &mut f, &mut Noop).unwrap_err();
        assert!(
            matches!(err, FindError::Unreachable { min: 1300, .. }),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn inconclusive_boundary_is_conservative_and_flagged() {
        let mut f = FakePinger::new(1450);
        f.flaky = true; // >1450 times out instead of being rejected
        let report = find_mtu(dst(), &range(), &mut f, &mut Noop).unwrap();
        assert_eq!(report.mtu, 1450);
        assert!(report.upper_inconclusive);
        assert!(!report.reached_range_max);
    }

    #[test]
    fn fatal_error_propagates() {
        let mut f = FakePinger::new(1450);
        f.fatal = Some("socket exploded".into());
        let err = find_mtu(dst(), &range(), &mut f, &mut Noop).unwrap_err();
        assert!(matches!(err, FindError::Fatal(_)));
    }

    #[test]
    fn single_size_range() {
        let r = MtuRange::new(1300, 1300).unwrap();
        let mut f = FakePinger::new(1300);
        let report = find_mtu(dst(), &r, &mut f, &mut Noop).unwrap();
        assert_eq!(report.mtu, 1300);
        assert!(report.reached_range_max);
        assert_eq!(f.probes, vec![1300]);
    }

    #[test]
    fn range_validation() {
        assert_eq!(MtuRange::new(1300, 1500).unwrap(), MtuRange { min: 1300, max: 1500 });
        assert!(MtuRange::new(1500, 1300).is_err(), "inverted range must fail");
        assert!(
            MtuRange::new(MIN_MTU - 1, 1500).is_err(),
            "below the IPv4+ICMP floor must fail"
        );
        assert!(MtuRange::new(MIN_MTU, 1500).is_ok(), "the floor itself is valid");
    }
}
