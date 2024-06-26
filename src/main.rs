
use clap::{App, Arg};
use std::net::{IpAddr,Ipv4Addr};
use std::time::Duration;
use indicatif::{ProgressBar, ProgressStyle};


struct MtuFinder {
    dst_ip: Ipv4Addr,
    min_mtu: u16,
    max_mtu: u16,
}

impl MtuFinder {
    fn new(dst_ip: Ipv4Addr, min_mtu: u16, max_mtu: u16) -> Self {
        MtuFinder {
            dst_ip,
            min_mtu,
            max_mtu,
        }
    }

    fn find_mtu(&self) -> u16 {
        let pb = ProgressBar::new((self.max_mtu - self.min_mtu) as u64);
        pb.set_style(ProgressStyle::default_bar()
            .template("{msg} {bar:40.cyan/blue} {percent}% ({eta})").expect("Invalid template")
            .progress_chars("##-"));


        let options = ping_rs::PingOptions { ttl: 128, dont_fragment: true };
        let timeout = Duration::from_secs(1);
        let mut last_working_mtu = self.min_mtu;

        for size in self.min_mtu..=self.max_mtu {
            pb.inc(1);
            let buffersize = size - 28; // 28 is the size of the IP header
            let data: Vec<u8> = (0..buffersize).map(|_| rand::random::<u8>()).collect();
            let ip_addr = IpAddr::V4(self.dst_ip);
            let response = ping_rs::send_ping(&ip_addr, timeout, &data, Some(&options));
            match response {
                Ok(_) =>  { 
                    last_working_mtu = size;
                },
                Err(_) => {
                    break;
                }
            }
        }
        pb.finish_with_message("MTU found!");
        last_working_mtu
    }
}

fn main() {
    let app = App::new("mtu_finder")
        .version("1.0")
        .author("Your Name")
        .about(" Finds the optimal MTU for a network connection")
        .arg(Arg::new("destination")
            .short('d')
            .long("destination")
            .takes_value(true)
            .required(true)
            .help("Destination IP address"))
        .arg(Arg::new("range")
            .short('r')
            .long("range")
            .takes_value(true)
            .default_value("1300:1500")
            .help("Range of MTU values to test (format: min:max)"));
   

    let matches = app.get_matches();

    let dst_ip = matches.value_of("destination").unwrap().parse::<Ipv4Addr>().unwrap();
    let range = matches.value_of("range").unwrap();
    let (min_mtu, max_mtu) = range.split_once(':').unwrap();
    let min_mtu: u16 = min_mtu.parse().unwrap();
    let max_mtu: u16 = max_mtu.parse().unwrap();
    println!("\x1b[1;34m🔍 mtu-finder:\x1b[0m \x1b[1;33mLooking for the optimal MTU\x1b[0m between \x1b[1;32m{}\x1b[0m and \x1b[1;32m{}\x1b[0m for connection to \x1b[1;35m{}\x1b[0m 🌐", min_mtu, max_mtu, dst_ip);
    let finder = MtuFinder::new(dst_ip, min_mtu, max_mtu);
    let mtu = finder.find_mtu();

    println!("Recommended MTU: {}", mtu);
    println!("Configuration suggestion: Set your MTU to {} for optimal performance.", mtu);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_mtu() {
        let dst_ip = Ipv4Addr::new(8, 8, 8, 8);
        let min_mtu = 1300;
        let max_mtu = 1500;
        let finder = MtuFinder::new(dst_ip, min_mtu, max_mtu);
        let mtu = finder.find_mtu();
        assert!(mtu >= min_mtu && mtu <= max_mtu);
    }

    #[test]
    fn test_new() {
        let dst_ip = Ipv4Addr::new(8, 8, 8, 8);
        let min_mtu = 1300;
        let max_mtu = 1500;
        let finder = MtuFinder::new(dst_ip, min_mtu, max_mtu);
        assert_eq!(finder.dst_ip, dst_ip);
        assert_eq!(finder.min_mtu, min_mtu);
        assert_eq!(finder.max_mtu, max_mtu);
    }
}
