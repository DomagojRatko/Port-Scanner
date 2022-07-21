#![allow(unused_doc_comments)]
#[macro_use]
extern crate clap;

use clap::{App, Arg, ArgMatches};
use std::thread;
use std::sync::mpsc::{Sender, channel};
use std::net::{TcpStream, IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use colored::Colorize;

/// It prints a banner to the terminal
fn print_banner() {
    println!("\n\n\n\n\n\n\n\n\n\n\n");
    println!("{}", format!("________              _____ ").red());
    println!("{}", format!("___  __ \\___  __________  /_").red());
    println!("{}", format!("__  /_/ /  / / /_  ___/  __/").red());
    println!("{}", format!("_  _, _// /_/ /_(__  )/ /_  ").red());
    println!("{}", format!("/_/ |_| \\__,_/ /____/ \\__/").red());
    println!("{}", format!(" _____   _____   ______ _______      _______ _______ _______ __   _ __   _ _______  ______").bold().green());
    println!("{}", format!("|_____] |     | |_____/    |         |______ |       |_____| | \\  | | \\  | |______ |_____/").bold().green());
    println!("{}", format!("|       |_____| |    \\_    |         ______| |_____  |     | |  \\_| |  \\_| |______ |    \\_\n").bold().green());
    println!("{}", format!("====================").bold().green());
    println!("{}", format!(" Rust Port Scanner").red());
    println!("{}", format!("====================").bold().green());
    println!("{} {}", format!("HELP:  ").yellow().bold() ,format!("port_scanner -h or --help").purple().italic());
    println!("{} {}", format!("USAGE: ").yellow().bold() ,format!("port_scanner -i 127.0.0.1 -t 500\n\n").purple().italic());
}

/// It prints the scan information to the console
///
/// Arguments:
///
/// * `ip`: The IP address of the target.
/// * `dispatched_threads`: The number of threads that will be dispatched to scan the IP address.
/// * `chunk_count`: The number of chunks that the IP address was split into.
fn print_scan_information(ip: &str, thread_count: usize, chunk_count: usize) {
    println!("{}", format!("{0: <15} | {1: <7} | {2: <7} | {3: <10}", "IP:ADDRESS", "THREADS", "TIMEOUT", "AVG CHUNK SIZE").red());
    println!("{}", format!("{0: <15} | {1: <7} | {2: <7} | {3: <10}", ip, thread_count, "5 sec" ,chunk_count).green());
    println!("\n\n{}", format!("{0: <15} | {1: <7} | {2: <7} | {3: <10}", "PORTS:", "STATUS", "THREADS", "TIME").red());
}

/// It prints the open ports to the console
fn print_open_ports(open_ports: Vec<u16>) {
    println!("{}", format!("\nCompleted scan. Opened TCP ports are:").red());
    println!("{}", format!("{:?}\n", &open_ports).green());
}

/// It creates a new instance of the App struct, which is provided by the clap crate.
fn app_structure() {
    let matches = App::new("Rust Port Scanner")
        .version("1.0")
        .author("Domagoj Ratko")
        .about("Simple multi-threaded port scan in Rust lang.")
        .arg(
            Arg::with_name("ip")
                .short("i".parse().unwrap())
                .long("ip")
                .takes_value(true)
                .help("The target IP Address to scan")
        )
        .arg(
            Arg::with_name("threads")
                .short("t".parse().unwrap())
                .long("threads")
                .takes_value(true)
                .help("Threads you want to perform")
        )
        .arg(
            Arg::with_name("quick")
                .short("q".parse().unwrap())
                .long("quick")
                .takes_value(false)
                .help_heading("Quick scan with max threads")
                .help("WARN: Will slow down operating system until done!")
        )
        .get_matches();

    app_logic(matches);
}

/// It takes the command line arguments, parses them, and then spawns a thread for each chunk of ports
/// to scan
///
/// Arguments:
///
/// * `matches`: ArgMatches - This is the struct that holds all the arguments that the user has passed
/// to the program.
fn app_logic(matches: ArgMatches) {
    let ip = matches.value_of("ip").unwrap_or("127.0.0.1");
    let mut thread_count = value_t!(matches, "threads", usize).unwrap_or(10);
    let quick_scan = matches.is_present("quick");
    let ip_address = ip.parse::<Ipv4Addr>().expect("Cannot parse your input into Ipv4Addr!");

    thread_count = quick_scan_check(thread_count, quick_scan);

    let (sender, receiver) = channel::<u16>();
    let mut open_ports: Vec<u16> = vec![];
    let socket_ports: Vec<u16> = (1..=65535).collect();

    thread_count_check(thread_count);

    let chunk_count = 65535 / thread_count;
    let mut dispatched_threads = 0;

    print_scan_information(ip,thread_count, chunk_count);

    /// Variable with Instant now to set scan start time.
    let start_time = Instant::now();

    /// Iterating over the socket_ports vector, and then it is taking a chunk of the vector,
    /// and then it is cloning the sender, and then it is spawning a new thread, and then it is calling
    /// the scan function.
    for chunk in socket_ports.chunks(chunk_count) {
        let chunk = chunk.to_owned();
        let sender = sender.clone();

        dispatched_threads += 1;

        thread::spawn(move || {
            scan(sender, chunk, ip_address, dispatched_threads, start_time);
        });
    }

    drop(sender);

    /// Receiving the open ports from the sender and then pushing them to the open_ports vector.
    for port in receiver {
        open_ports.push(port);
    }

    print_open_ports(open_ports);
}

/// It takes a sender, a vector of ports, and an IP address, and then it tries to connect to each port
/// on the IP address. If it can connect, it prints the port number and the word "OPEN", and
/// then it sends the port number to the sender
fn scan(sender: Sender<u16>, range: Vec<u16>, ip_address: Ipv4Addr, dispatched_threads: i32, start_time: Instant) {
    for port_number in range {
        let socket = SocketAddr::new(IpAddr::from(ip_address), port_number);
        if TcpStream::connect_timeout(&socket, Duration::new(5, 0)).is_ok() {
            println!("{}", format!("{0: <15} | {1: <7} | {2: <7} | {3: <1} sec",port_number,"OPEN", dispatched_threads, start_time.elapsed().as_secs()).green());
            sender.send(port_number).unwrap();
        }
    }
}

/// Checking if the user has passed the `-q` or `--quick` argument to the program. If he has,
/// If quick_scan is true, return max thread count of 65534,
/// else return the thread_count.
fn quick_scan_check(thread_count: usize, quick_scan: bool) -> usize {
    return if quick_scan == true {
        65534
    } else {
        thread_count
    }
}

/// It checks if the number of threads is larger than 65535 or smaller than 1. If it is, it panics
fn thread_count_check(thread_count: usize) {
    if thread_count > 65535 || thread_count < 1 {
        println!("{}", format!("Try with -t 1000").yellow().bold());
        panic!("{}", format!("Threads count can't be larger than 65535 or smaller than 1").red().bold());
    }
}

/// `main()` is the entry point of the application
fn main() {
    print_banner();
    app_structure();
}