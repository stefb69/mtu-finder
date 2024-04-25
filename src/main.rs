
use clap::{App, Arg};
use std::net::{IpAddr,Ipv4Addr};
use std::time::Duration;
use indicatif::{ProgressBar, ProgressStyle};


struct MtuFinder {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    min_mtu: u16,
    max_mtu: u16,
}

impl MtuFinder {
    fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, min_mtu: u16, max_mtu: u16) -> Self {
        MtuFinder {
            src_ip,
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
 //           let ping = Ping::new(self.src_ip, self.dst_ip, buffersize, PingFlags::DF);
//            let data = vec![255; buffersize];
            let data: Vec<u8> = (0..buffersize).map(|_| rand::random::<u8>()).collect();
            let ip_addr = IpAddr::V4(self.dst_ip);
            let response = ping_rs::send_ping(&ip_addr, timeout, &data, Some(&options));
            match response {
                Ok(reply) =>  { 
                    println!("Reply from {}: bytes={} time={}ms TTL={}", reply.address, data.len(), reply.rtt, options.ttl);
                    last_working_mtu = size;
                },
                Err(e) => {
                    println!("{:?}", e);
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
        .arg(Arg::new("source")
            .short('s')
            .long("source")
            .takes_value(true)
            .default_value("0.0.0.0")
            .help("Source IP address (optional)"))
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

    let src_ip = matches.value_of("source").unwrap().parse::<Ipv4Addr>().unwrap();
    let dst_ip = matches.value_of("destination").unwrap().parse::<Ipv4Addr>().unwrap();
    let range = matches.value_of("range").unwrap();
    let (min_mtu, max_mtu) = range.split_once(':').unwrap();
    let min_mtu: u16 = min_mtu.parse().unwrap();
    let max_mtu: u16 = max_mtu.parse().unwrap();

    let finder = MtuFinder::new(src_ip, dst_ip, min_mtu, max_mtu);
    let mtu = finder.find_mtu();

    println!("Recommended MTU: {}", mtu);
    println!("Configuration suggestion: Set your MTU to {} for optimal performance.", mtu);
}