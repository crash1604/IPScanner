use std::net::{IpAddr, SocketAddr, TcpStream};
use std::str::FromStr;
use std::time::Duration;
use clap::{App, Arg};
use threadpool::ThreadPool;
use std::sync::Arc;
use std::sync::Mutex;

// Main function
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

    let start_ip = matches.value_of("start_ip").unwrap();
    let end_ip = matches.value_of("end_ip").unwrap();
    let ports_str = matches.value_of("ports").unwrap();
    let timeout = matches.value_of("timeout").unwrap().parse::<u64>().unwrap();
    let threads = matches.value_of("threads").unwrap().parse::<usize>().unwrap();

    let ports: Vec<u16> = ports_str
        .split(',')
        .map(|p| p.trim().parse::<u16>().unwrap())
        .collect();

    println!("Starting scan from {} to {}", start_ip, end_ip);
    println!("Scanning ports: {:?}", ports);
    println!("Timeout: {}ms, Threads: {}", timeout, threads);

    let start = ip_to_u32(start_ip).unwrap();
    let end = ip_to_u32(end_ip).unwrap();
    let timeout = Duration::from_millis(timeout);

    let pool = ThreadPool::new(threads);
    let ports = Arc::new(ports);
    let results = Arc::new(Mutex::new(Vec::new())); // For storing output

    for ip_num in start..=end {
        let ip = u32_to_ip(ip_num);
        let ports = Arc::clone(&ports);
        let timeout = timeout.clone();
        let results = Arc::clone(&results);

        pool.execute(move || {
            let open_ports = scan_ip(ip, &ports, timeout);
            if !open_ports.is_empty() {
                let mut r = results.lock().unwrap();
                r.push((ip, open_ports));
            }
        });
    }

    pool.join(); // Wait for all threads to complete

    // Print final results
    let results = results.lock().unwrap();
    for (ip, open_ports) in results.iter() {
        println!("{} is active. Open ports: {:?}", ip, open_ports);
    }

    println!("Scan completed!");
}

fn scan_ip(ip: IpAddr, ports: &[u16], timeout: Duration) -> Vec<u16> {
    let mut open = Vec::new();
    for &port in ports {
        let socket = SocketAddr::new(ip, port);
        if TcpStream::connect_timeout(&socket, timeout).is_ok() {
            open.push(port);
        }
    }
    open
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
        IpAddr::V6(_) => None,
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
