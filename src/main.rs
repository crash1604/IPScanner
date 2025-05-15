use std::net::{IpAddr, SocketAddr, TcpStream};
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;
use clap::{App, Arg};
use threadpool::ThreadPool;
use std::sync::{Arc, Mutex};
use serde::Serialize;
use std::fs::File;
use std::io::Write;

#[derive(Serialize)]
struct ScanResult {
    ip: IpAddr,
    open_ports: Vec<u16>,
}

fn main() {
    let matches = App::new("Rust IP Scanner")
        .version("1.1")
        .author("Chanakya Sharma")
        .about("Scans IP addresses for open ports")
        .arg(Arg::with_name("start_ip").required(true).index(1))
        .arg(Arg::with_name("end_ip").required(true).index(2))
        .arg(
            Arg::with_name("ports")
                .short("p")
                .long("ports")
                .default_value("80,443,22,3389"),
        )
        .arg(
            Arg::with_name("timeout")
                .short("t")
                .long("timeout")
                .default_value("500"),
        )
        .arg(
            Arg::with_name("threads")
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

    println!("Scanning from {} to {}", start_ip, end_ip);

    let start = ip_to_u32(start_ip).unwrap();
    let end = ip_to_u32(end_ip).unwrap();
    let timeout = Duration::from_millis(timeout);

    if start > end {
    eprintln!("Start IP must be less than or equal to End IP");
    return;
}

    let pool = ThreadPool::new(threads);
    let ports = Arc::new(ports);
    let results = Arc::new(Mutex::new(Vec::new()));

    for ip_num in start..=end {
        let ip = u32_to_ip(ip_num);
        let ports = Arc::clone(&ports);
        let timeout = timeout.clone();
        let results = Arc::clone(&results);

        pool.execute(move || {
            if !ping_host(&ip) {
                return;
            }

            let open_ports = scan_ip(ip, &ports, timeout);
            if !open_ports.is_empty() {
                let mut r = results.lock().unwrap();
                println!("IP: {}, Open Ports: {:?}", ip, open_ports);
                r.push(ScanResult { ip, open_ports });
            }
        });
    }

    pool.join();

    // Write results to file
    let results = results.lock().unwrap();
    let json = serde_json::to_string_pretty(&*results).unwrap();
    let mut file = File::create("scan_results.json").expect("Failed to create output file");
    file.write_all(json.as_bytes()).expect("Failed to write output");

    println!("Scan completed. Results saved to scan_results.json");
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

fn ping_host(ip: &IpAddr) -> bool {
    let ip_str = ip.to_string();
    let output = if cfg!(target_os = "windows") {
        Command::new("ping")
            .args(&["-n", "1", "-w", "1000", &ip_str])
            .output()
    } else {
        Command::new("ping")
            .args(&["-c", "1", "-W", "1", &ip_str])
            .output()
    };

    if let Ok(output) = output {
        output.status.success()
    } else {
        false
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_ip_to_u32_and_back() {
        let ip_str = "192.168.1.1";
        let ip_u32 = ip_to_u32(ip_str).unwrap();
        let ip_back = u32_to_ip(ip_u32);

        assert_eq!(IpAddr::from_str(ip_str).unwrap(), ip_back);
    }

    #[test]
    fn test_ip_to_u32_valid() {
        assert_eq!(ip_to_u32("0.0.0.0").unwrap(), 0);
        assert_eq!(ip_to_u32("255.255.255.255").unwrap(), u32::MAX);
        assert_eq!(ip_to_u32("10.0.0.1").unwrap(), (10 << 24) + 1);
    }

    #[test]
    fn test_ip_to_u32_invalid() {
        assert!(ip_to_u32("999.999.999.999").is_none());
        assert!(ip_to_u32("abc.def.ghi.jkl").is_none());
        assert!(ip_to_u32("::1").is_none()); // IPv6 not supported
    }

    #[test]
    fn test_ports_parsing() {
        let ports_str = "80,443,22,3389";
        let ports: Vec<u16> = ports_str
            .split(',')
            .map(|p| p.trim().parse::<u16>().unwrap())
            .collect();
        assert_eq!(ports, vec![80, 443, 22, 3389]);
    }

    #[test]
    fn test_u32_to_ip() {
        let ip = u32_to_ip(0xC0A80101); // 192.168.1.1
        assert_eq!(ip.to_string(), "192.168.1.1");
    }
}
