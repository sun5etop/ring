use std::backtrace::Backtrace;
use std::net::{self, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::{mem, ptr, thread};
use std::time::{Duration, Instant};

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{checksum, Ipv4Flags};
use pnet::packet::ipv4::Ipv4Packet;  
use pnet::packet::ipv4::MutableIpv4Packet;  
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::{IcmpCodes, MutableEchoRequestPacket};
use pnet::packet::icmp::{self, IcmpTypes};
use pnet::packet::{util, MutablePacket, Packet};
use libc::{c_int, c_void, SIGINT, SIGTERM, sigaction, SA_SIGINFO, siginfo_t};

use rand::random;
//use signal_hook::consts::{SIGINT, SIGTERM};

use socket2::{Domain, Protocol, Socket, Type};

use crossbeam_channel::{self, bounded, select, Receiver};

use crate::config::Config;
use crate::error::RingError;

#[derive(Clone)]
pub struct Pinger {
    config: Config,
    dest: SocketAddr,
    socket: Arc<Socket>,
}

impl Pinger {
    pub fn new(config: Config) -> std::io::Result<Self> {
        //let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?; 
        //let src = SocketAddr::new(net::IpAddr::V4(Ipv4Addr::new(192, 168, 69, 0)), 0);
        let dest = SocketAddr::new(config.destination.ip, 0);
        //socket.bind(&src.into())?;
        //socket.set_ttl(config.ttl)?;
        socket.set_read_timeout(Some(Duration::new(config.timeout, 0)))?;
        socket.set_write_timeout(Some(Duration::new(config.timeout, 0)))?;
        Ok(Self {
            config: config,
            dest: dest,
            socket: Arc::new(socket),
        })
    }

    pub fn run(&self) -> std::io::Result<()> {
        println!(
            "PING {}({})",
            self.config.destination.raw, self.config.destination.ip
        );
        let now = Instant::now();
        let send = Arc::new(AtomicU64::new(0));
        let _send = send.clone();
        let this = Arc::new(self.clone());
        //let (sx, rx) = bounded(this.config.count as usize);

        let success = Arc::new(AtomicU64::new(0));
        let _success = success.clone();

        //thread::spawn(move || {
            for i in 0..this.config.count {
                let _this = this.clone();
                    //sx.send(thread::spawn(move || {
                        match _this.ping(i){
                            Ok(())=>{
                                _success.fetch_add(1, Ordering::SeqCst);
                            }
                            Err(error) => {
                                eprintln!("error while ping!: {}", error);
                            }
                        }
                    //})).unwrap();
                _send.fetch_add(1, Ordering::SeqCst);
                if i < this.config.count - 1 {
                    thread::sleep(Duration::from_millis(1000));
                }
            }
            //drop(sx);
        //});

        //let (summary_s, summary_r) = bounded(1);
        // thread::spawn(move || {
        //     println!("seems error1111 here");
        //     for handle in rx.iter() {
        //         println!("seems erroriii here");
        //         if let Some(res) = handle.join().ok() {
        //             println!("seems error inside here");
        //             if res.is_ok() {
        //                 _success.fetch_add(1, Ordering::SeqCst);
        //             }
        //         }
        //     }
        //     summary_s.send(()).unwrap();
        // });

        // let stop = signal_notify()?;
        // select!(
        //     recv(stop) -> sig => {
        //         if let Some(s) = sig.ok() {
        //             println!("Receive signal {:?}", s);
        //         }
        //     },
        //     recv(summary_r) -> summary => {
        //         if let Some(e) = summary.err() {
        //             println!("Error on summary: {}", e);
        //         }
        //     },
        // );

        let total = now.elapsed().as_micros() as f64 / 1000.0;
        let send = send.load(Ordering::SeqCst);
        let success = success.load(Ordering::SeqCst);
        let loss_rate = if send > 0 {
            (send - success) * 100 / send
        } else {
            0
        };
        println!("\n--- {} ping statistics ---", self.config.destination.raw);
        println!(
            "{} packets transmitted, {} received, {}% packet loss, time {}ms",
            send, success, loss_rate, total,
        );
        println!("finished");
        Ok(())
    }

    pub fn ping(&self, seq_offset: u16) -> anyhow::Result<()> {
        // create icmp request packet
        //let mut buf = vec![0; self.config.packet_size];
        let mut buf = vec![0; 64];   

        let mut icmp_header:[u8;64] = [0;64];
        let mut icmp = create_icmp_packet(&mut icmp_header);
        let start = Instant::now();

        // send request
        self.socket.send_to(icmp.packet_mut(), &self.dest.into())?;

        // handle recv
        let mut mem_buf =
            unsafe { &mut *(buf.as_mut_slice() as *mut [u8] as *mut [std::mem::MaybeUninit<u8>]) };
        let (size, _) = self.socket.recv_from(&mut mem_buf)?;
        
        let duration = start.elapsed().as_micros() as f64 / 1000.0;
        let reply = EchoReplyPacket::new(&buf).ok_or(RingError::InvalidPacket)?;
        println!(
            "{} bytes from {}: icmp_seq={} ttl={} time={:.2}ms",
            size,
            self.config.destination.ip,
            reply.get_sequence_number(),
            self.config.ttl,
            duration
        );
        Ok(())
    }
}

// fn signal_notify() -> std::io::Result<Receiver<i32>> {
//     let (s, r) = bounded(1);

//     let mut signals = signal_hook::iterator::Signals::new(&[SIGINT, SIGTERM])?;

//     thread::spawn(move || {
//         for signal in signals.forever() {
//             s.send(signal).unwrap();
//             break;
//         }
//     });


//     Ok(r)
// }
static mut SENDER: Option<crossbeam_channel::Sender<c_int>> = None;
extern "C" fn signal_handler(sig: c_int, _: *mut siginfo_t, _: *mut libc::c_void) {
    // 通过通道发送收到的信号
    if let Some(sender) = unsafe { SENDER.as_ref() } {
        sender.send(sig).unwrap();
    }
}

fn signal_notify() -> std::io::Result<Receiver<c_int>> {
    // 创建一个通道，用于发送信号
    // 创建一个通道，用于发送信号
    let (sender, receiver) = bounded(1);
    unsafe {
        SENDER = Some(sender);
    }

    // 设置信号处理函数
    let mut act: sigaction = unsafe { mem::zeroed() };
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = unsafe { mem::transmute(signal_handler as usize) }; // 显式转换

    // 捕获SIGINT信号
    if unsafe { sigaction(SIGINT, &act, ptr::null_mut()) } == -1 {
        return Err(std::io::Error::last_os_error());
    }

    // 捕获SIGTERM信号
    if unsafe { sigaction(SIGTERM, &act, ptr::null_mut()) } == -1 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(receiver)
}

fn create_icmp_packet<'a>(icmp_header: &'a mut [u8]) -> MutableEchoRequestPacket<'a> {
    let mut icmp_packet = MutableEchoRequestPacket::new(icmp_header).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);
    icmp_packet.set_icmp_code(IcmpCodes::NoCode);
    icmp_packet.set_identifier(random::<u16>());
    icmp_packet.set_sequence_number(1);
    let checksum = util::checksum(icmp_packet.packet(), 1);
    icmp_packet.set_checksum(checksum);

    icmp_packet
}
struct IpHeader {  
    version_ihl: u8,  // 版本和头部长度  
    tos: u8,          // 服务类型  
    total_length: u16, // 总长度  
    identification: u16, // 标识符  
    flags_fragment_offset: u16, // 标志和分段偏移  
    ttl: u8,          // 生存时间  
    protocol: u8,     // 协议  
    checksum: u16,    // 校验和  
    source_ip: Ipv4Addr, // 源IP地址  
    destination_ip: Ipv4Addr, // 目标IP地址  
} 