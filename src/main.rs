//! mtu-finder: find the optimal MTU for a network connection.
//!
//! Exit codes:
//! * `0` — a working MTU was found and reported.
//! * `1` — runtime error (unreachable destination, backend failure).
//! * `2` — invalid command-line arguments (handled by clap).

mod icmp;
mod search;

use clap::Parser;
use icmp::{create_pinger, ProbeOutcome};
use indicatif::{ProgressBar, ProgressStyle};
use search::{find_mtu, MtuRange, ProbeReport, ProgressReporter};
use std::net::Ipv4Addr;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "mtu-finder",
    version = env!("CARGO_PKG_VERSION"),
    about = "Find the optimal MTU for a network connection"
)]
struct Cli {
    /// Destination IPv4 address to probe
    #[arg(short, long, value_name = "IP")]
    destination: Ipv4Addr,

    /// Range of MTU values to test (format: min:max)
    #[arg(
        short,
        long,
        default_value = "1300:1500",
        value_name = "MIN:MAX",
        value_parser = parse_range
    )]
    range: MtuRange,
}

/// Parse and validate a `MIN:MAX` range in one step so bad input becomes a
/// clean clap error instead of a panic.
fn parse_range(s: &str) -> Result<MtuRange, String> {
    let (min, max) = s
        .split_once(':')
        .ok_or_else(|| "expected MIN:MAX".to_string())?;
    let min: u16 = min
        .trim()
        .parse()
        .map_err(|_| format!("invalid minimum MTU '{min}'"))?;
    let max: u16 = max
        .trim()
        .parse()
        .map_err(|_| format!("invalid maximum MTU '{max}'"))?;
    MtuRange::new(min, max)
}

struct TerminalReporter {
    bar: ProgressBar,
}

impl TerminalReporter {
    fn new(range: &MtuRange, dst: Ipv4Addr) -> Self {
        println!(
            "\x1b[1;34m🔍 mtu-finder:\x1b[0m \x1b[1;33mLooking for the optimal MTU\x1b[0m between \x1b[1;32m{}\x1b[0m and \x1b[1;32m{}\x1b[0m for connection to \x1b[1;35m{}\x1b[0m 🌐",
            range.min, range.max, dst
        );
        // Binary search probe count is data-dependent, so use a spinner
        // instead of a determinate bar.
        let bar = ProgressBar::new_spinner();
        bar.enable_steady_tick(Duration::from_millis(100));
        bar.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg}").expect("valid template"),
        );
        Self { bar }
    }
}

impl ProgressReporter for TerminalReporter {
    fn probing(&mut self, size: u16) {
        self.bar
            .set_message(format!("probing {size} bytes…"));
    }

    fn result(&mut self, size: u16, outcome: &ProbeOutcome) {
        let label = match outcome {
            ProbeOutcome::Fits => "fits",
            ProbeOutcome::TooLarge => "too large",
            ProbeOutcome::Inconclusive => "no reply (inconclusive)",
            ProbeOutcome::Fatal(_) => "error",
        };
        self.bar.set_message(format!("{size} bytes → {label}"));
    }

    fn finish(&mut self, message: &str) {
        self.bar.finish_with_message(message.to_string());
    }
}

fn print_report(report: &ProbeReport) {
    println!(
        "\x1b[1;32m✅ Recommended MTU:\x1b[0m \x1b[1m{}\x1b[0m",
        report.mtu
    );
    if report.reached_range_max {
        println!(
            "   note: this is the top of the tested range — the true MTU may be higher, try a wider -r range"
        );
    }
    if report.upper_inconclusive {
        println!(
            "   note: sizes above {} timed out rather than being rejected; the true MTU may be slightly higher",
            report.mtu
        );
    }
    println!(
        "Configuration suggestion: Set your MTU to {} for optimal performance.",
        report.mtu
    );
}

fn main() {
    let cli = Cli::parse();

    let mut pinger = match create_pinger() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: failed to open ICMP socket: {e}");
            std::process::exit(1);
        }
    };

    let mut reporter = TerminalReporter::new(&cli.range, cli.destination);
    match find_mtu(cli.destination, &cli.range, &mut *pinger, &mut reporter) {
        Ok(report) => {
            reporter.finish("MTU found!");
            print_report(&report);
        }
        Err(e) => {
            reporter.finish("failed");
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_range() {
        assert_eq!(
            parse_range("1300:1500").unwrap(),
            MtuRange {
                min: 1300,
                max: 1500
            }
        );
        // Whitespace tolerance.
        assert_eq!(parse_range(" 1300 : 1500 ").unwrap().min, 1300);
    }

    #[test]
    fn rejects_bad_ranges() {
        assert!(parse_range("1500").is_err(), "missing colon");
        assert!(parse_range("1500:1300").is_err(), "inverted");
        assert!(parse_range("20:1500").is_err(), "below the 28-byte floor");
        assert!(parse_range("abc:1500").is_err(), "non-numeric min");
        assert!(parse_range("1300:xyz").is_err(), "non-numeric max");
        assert!(parse_range("70000:80000").is_err(), "u16 overflow");
        assert!(parse_range("").is_err(), "empty");
    }
}
