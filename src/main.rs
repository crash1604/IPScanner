use std::net::{IpAddr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::sync::mpsc::{channel};
use std::thread;
use std::time::Duration;
use clap::{App, Arg};


// main function
fn main() {
    let matches = App::new("Rust IP Scanner")
        .version("1.0")
        .author("Chanakya Sharma <chanakyadevpro@gmail.com>")
        .about("Scans IP addresses for open ports")
        .arg(
            Arg::with_name("start_ip")
                .help("The starting IP address")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("end_ip")
                .help("The ending IP address")
                .required(true)
                .index(2),
        )
        .arg(
            Arg::with_name("ports")
                .help("Ports to scan (comma-separated)")
                .short("p")
                .long("ports")
                .default_value("80,443,22,3389"),
        )
        .arg(
            Arg::with_name("timeout")
                .help("Connection timeout in milliseconds")
                .short("t")
                .long("timeout")
                .default_value("500"),
        )
        .arg(
            Arg::with_name("threads")
                .help("Number of threads to use")
                .short("n")
                .long("threads")
                .default_value("100"),
        )
        .get_matches();

    // assign values and variables from args
    let start_ip = matches.value_of("start_ip").unwrap();
    let end_ip = matches.value_of("end_ip").unwrap();
    let ports_str = matches.value_of("ports").unwrap();
    let timeout = matches.value_of("timeout").unwrap().parse::<u64>().unwrap();
    let threads = matches.value_of("threads").unwrap().parse::<u32>().unwrap();

    // list of ports in var vec of u16
    let ports: Vec<u16> = ports_str
        .split(',')
        .map(|p| p.trim().parse::<u16>().unwrap())
        .collect();
    
    // generic print statements
    println!("Starting scan from {} to {}", start_ip, end_ip);
    println!("Scanning ports: {:?}", ports);
    println!("Timeout: {}ms, Threads: {}", timeout, threads);

    // assign start and end date
    let start = ip_to_u32(start_ip).unwrap();
    let end = ip_to_u32(end_ip).unwrap();

    let (tx, rx) = channel();
    let mut active_threads = 0;

    // loop 
    for ip_num in start..=end {
        let ip = u32_to_ip(ip_num);
        let ports = ports.clone();
        let tx = tx.clone();
        let timeout = Duration::from_millis(timeout);

        // Wait if we've reached the thread limit
        while active_threads >= threads {
            active_threads = rx.recv().unwrap();
        }

        active_threads += 1;
        thread::spawn(move || {
            scan_ip(ip, &ports, timeout);
            tx.send(active_threads - 1).unwrap();
        });
    }

    // Wait for all threads to complete
    while active_threads > 0 {
        active_threads = rx.recv().unwrap();
    }

    println!("Scan completed!");
}

fn scan_ip(ip: IpAddr, ports: &[u16], timeout: Duration) {
    for &port in ports {
        let socket = SocketAddr::new(ip, port);
        if TcpStream::connect_timeout(&socket, timeout).is_ok() {
            println!("{}:{} is open", ip, port);
        }
    }
}

fn ip_to_u32(ip_str: &str) -> Option<u32> {
    let ip = IpAddr::from_str(ip_str).ok()?;
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            Some(
                (octets[0] as u32) << 24 |
                (octets[1] as u32) << 16 |
                (octets[2] as u32) << 8 |
                (octets[3] as u32)
            )
        }
        IpAddr::V6(_) => None, // IPv6 not supported in this simple scanner
    }
}

fn u32_to_ip(ip_num: u32) -> IpAddr {
    let octets = [
        ((ip_num >> 24) & 0xFF) as u8,
        ((ip_num >> 16) & 0xFF) as u8,
        ((ip_num >> 8) & 0xFF) as u8,
        (ip_num & 0xFF) as u8,
    ];
    IpAddr::from(octets)
}