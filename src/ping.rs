use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;
use socket2::{Domain, Protocol, Socket, Type, SockAddr};
use anyhow::Result;
use std::mem::MaybeUninit;

const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

struct IcmpHeader {
    type_: u8,
    code: u8,
    checksum: u16,
    identifier: u16,
    sequence: u16,
}

impl IcmpHeader {
    fn new(identifier: u16, sequence: u16) -> Self {
        Self {
            type_: ICMP_ECHO_REQUEST,
            code: 0,
            checksum: 0,
            identifier,
            sequence,
        }
    }

    fn to_bytes(&self) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0] = self.type_;
        bytes[1] = self.code;
        bytes[2..4].copy_from_slice(&self.checksum.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.identifier.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.sequence.to_be_bytes());
        bytes
    }

    fn calculate_checksum(&mut self) {
        let mut sum = 0u32;
        let bytes = self.to_bytes();
        
        // 计算校验和
        for i in (0..bytes.len()).step_by(2) {
            if i + 1 < bytes.len() {
                sum += u32::from(u16::from_be_bytes([bytes[i], bytes[i + 1]]));
            }
        }
        
        // 处理进位
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        
        self.checksum = !sum as u16;
    }
}

pub async fn ping(target: IpAddr, timeout_duration: Duration) -> bool {
    // 尝试连接常见端口
    let test_ports = [80, 443, 22, 3389];
    
    for port in test_ports {
        let addr = SocketAddr::new(target, port);
        if let Ok(Ok(_)) = timeout(timeout_duration, TcpStream::connect(addr)).await {
            return true;
        }
    }

    // 如果常见端口都不可达，尝试 ICMP ping
    if let IpAddr::V4(ipv4) = target {
        if let Ok(result) = icmp_ping(ipv4, timeout_duration).await {
            return result;
        }
    }

    false
}

async fn icmp_ping(target: Ipv4Addr, timeout_duration: Duration) -> Result<bool> {
    // 创建原始套接字
    let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    socket.set_read_timeout(Some(timeout_duration))?;
    socket.set_write_timeout(Some(timeout_duration))?;

    // 准备 ICMP 包
    let mut header = IcmpHeader::new(1, 1);
    header.calculate_checksum();
    let packet = header.to_bytes();

    // 发送 ICMP 包
    let target_addr = SockAddr::from(SocketAddr::new(IpAddr::V4(target), 0));
    socket.send_to(&packet, &target_addr)?;

    // 接收响应
    let mut buffer = [MaybeUninit::uninit(); 1024];
    match socket.recv_from(&mut buffer) {
        Ok((len, _)) => {
            if len >= 8 {
                let reply_type = unsafe { buffer[0].assume_init() };
                return Ok(reply_type == ICMP_ECHO_REPLY);
            }
        }
        Err(_) => {}
    }

    Ok(false)
} 