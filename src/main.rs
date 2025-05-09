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
            if ping_only {
                if !ping(target, timeout).await {
                    return Ok::<(Vec<(u16, String)>, Output), anyhow::Error>((Vec::new(), Output::new(target.to_string())));
                }
            }

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

            // 只返回服务识别结果
            let service_results = scanner.run().await?;

            // 操作系统识别
            let mut output = Output::new(target.to_string());
            let os_detector = OSDetector::new(target);
            if let Ok(os_info) = os_detector.detect().await {
                output.set_os_info(os_info);
                progress.set_os_detected();
            }

            // 填充端口和服务
            for (port, service) in &service_results {
                output.add_port(*port, service.clone(),
                    if matches!(scan_type, ScanType::Tcp) { "TCP" } else { "UDP" }.to_string()
                );
            }

            // 保存结果
            if let Some(path) = &json_output {
                output.save_json(path)?;
            }
            if let Some(path) = &csv_output {
                output.save_csv(path)?;
            }

            Ok((service_results, output))
        });

        tasks.push(task);
    }

    // 等待所有扫描任务完成，统一 finish 进度条和输出
    for task in tasks {
        match task.await? {
            Ok((service_results, output)) => {
                progress.finish();
                // 先输出服务识别结果
                if !service_results.is_empty() {
                    println!("\n开放端口与服务：");
                    for (port, service) in service_results {
                        println!("  - 端口 {}: {}", port, service);
                    }
                } else {
                    println!("\n未发现开放端口。");
                }
                // 再输出统计信息
                output.print_console();
            }
            Err(e) => {
                progress.finish();
                eprintln!("扫描出错: {}", e);
            }
        }
    }

    // 完成进度显示
    progress.finish();

    Ok(())
}