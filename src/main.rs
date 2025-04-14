mod scanner;
mod service_detector;
mod os_detector;
mod output;
mod service_fingerprints;
mod rate_controller;
mod progress;

use clap::Parser;
use colored::*;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

use rustscan::scanner::{Scanner, ScanType};
use rustscan::service_detector::ServiceDetector;
use rustscan::os_detector::OSDetector;
use rustscan::output::Output;
use rustscan::progress::ScanProgress;
use rustscan::ping::ping;
use rustscan::rate_controller::RateController;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 目标IP地址或网段 (例如: 192.168.1.1 或 192.168.1.0/24)
    #[arg(short = 'i', long)]
    target: String,

    /// 起始端口
    #[arg(short = 's', long, default_value_t = 1)]
    start_port: u16,

    /// 结束端口
    #[arg(short = 'e', long, default_value_t = 65535)]
    end_port: u16,

    /// 超时时间（毫秒）
    #[arg(short = 'o', long, default_value_t = 200)]
    timeout: u64,

    /// 并发数
    #[arg(short = 'c', long, default_value_t = 1000)]
    threads: usize,

    /// 扫描类型 (tcp/udp)
    #[arg(short = 't', long, default_value = "tcp")]
    scan_type: String,

    /// 输出JSON文件路径
    #[arg(short = 'j', long)]
    json_output: Option<PathBuf>,

    /// 输出CSV文件路径
    #[arg(short = 'C', long)]
    csv_output: Option<PathBuf>,

    /// 是否只扫描存活主机
    #[arg(short = 'p', long, default_value_t = false)]
    ping_only: bool,
}

fn parse_subnet(subnet: &str) -> Result<Vec<IpAddr>> {
    if subnet.contains('/') {
        let (ip_str, mask_str) = subnet.split_once('/').unwrap();
        let base_ip: Ipv4Addr = ip_str.parse()?;
        let mask: u8 = mask_str.parse()?;
        
        if mask > 32 {
            return Err(anyhow::anyhow!("无效的子网掩码"));
        }

        let mut ips = Vec::new();
        let host_bits = 32 - mask;
        let num_hosts = 1u32 << host_bits;
        let base_ip_u32 = u32::from_be_bytes(base_ip.octets());
        let network_addr = base_ip_u32 & (!0u32 << host_bits);
        
        // 跳过网络地址和广播地址
        for i in 1..num_hosts-1 {
            let ip_u32 = network_addr | i;
            let ip = Ipv4Addr::from(ip_u32);
            ips.push(IpAddr::V4(ip));
        }
        
        Ok(ips)
    } else {
        Ok(vec![subnet.parse()?])
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // 解析目标地址或网段
    let targets = parse_subnet(&args.target)?;
    let timeout = Duration::from_millis(args.timeout);
    let total_ports = (args.end_port - args.start_port + 1) as u64;
    let total_targets = targets.len() as u64;

    // 解析扫描类型
    let scan_type = match args.scan_type.to_lowercase().as_str() {
        "tcp" => ScanType::Tcp,
        "udp" => ScanType::Udp,
        _ => {
            eprintln!("无效的扫描类型，使用默认值 TCP");
            ScanType::Tcp
        }
    };

    println!("{} 开始{}扫描 {} 个目标...", 
        "[*]".blue(), 
        if matches!(scan_type, ScanType::Tcp) { "TCP" } else { "UDP" },
        total_targets
    );

    // 创建进度显示器
    let progress = Arc::new(ScanProgress::new(total_ports * total_targets, total_targets));

    // 并行扫描所有目标
    let mut tasks = Vec::new();
    for target in targets {
        let progress = progress.clone();
        let scan_type = scan_type.clone();
        let ping_only = args.ping_only;
        let start_port = args.start_port;
        let end_port = args.end_port;
        let threads = args.threads;
        let json_output = args.json_output.clone();
        let csv_output = args.csv_output.clone();

        let task = tokio::spawn(async move {
            // 如果启用了ping扫描，先检查主机是否存活
            if ping_only {
                if !ping(target, timeout).await {
                    return Ok::<Vec<u16>, anyhow::Error>(Vec::new());
                }
            }

            // 创建扫描器
            let scanner = Scanner::new(
                target,
                start_port,
                end_port,
                timeout,
                threads,
                progress.clone(),
                Arc::new(Mutex::new(RateController::new(threads as u64 * 1000, (threads / 10).max(1) as u64))),
                scan_type.clone(),
                Arc::new(ServiceDetector::new()),
            );

            // 执行端口扫描
            let open_ports = scanner.run_tcp_scan().await?;

            // 创建输出对象
            let mut output = Output::new(target.to_string());

            // 设置服务识别进度条
            progress.set_total_services(open_ports.len() as u64);

            // 操作系统识别
            let os_detector = OSDetector::new(target);
            if let Ok(os_info) = os_detector.detect().await {
                output.set_os_info(os_info);
                progress.set_os_detected();
            }

            // 服务识别
            let open_ports_clone = open_ports.clone();
            for port in open_ports_clone {
                let detector = ServiceDetector::new();
                if let Ok(Some(service)) = detector.detect(target, port).await {
                    output.add_port(port, service, 
                        if matches!(scan_type, ScanType::Tcp) { "TCP" } else { "UDP" }.to_string()
                    );
                }
                progress.increment_service_detect();
            }

            // 输出结果
            output.print_console();

            // 保存结果
            if let Some(path) = &json_output {
                output.save_json(path)?;
                println!("{} 结果已保存到: {:?}", "[*]".blue(), path);
            }

            if let Some(path) = &csv_output {
                output.save_csv(path)?;
                println!("{} 结果已保存到: {:?}", "[*]".blue(), path);
            }

            Ok(open_ports)
        });

        tasks.push(task);
    }

    // 等待所有扫描任务完成
    for task in tasks {
        if let Err(e) = task.await? {
            eprintln!("扫描出错: {}", e);
        }
    }

    // 完成进度显示
    progress.finish();

    Ok(())
}