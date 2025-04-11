mod scanner;
mod service_detector;
mod os_detector;
mod output;
mod service_fingerprints;
mod rate_controller;
mod progress;

use clap::Parser;
use colored::*;
use std::net::IpAddr;
use std::time::Duration;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;

use crate::scanner::{Scanner, ScanType};
use crate::service_detector::ServiceDetector;
use crate::os_detector::OSDetector;
use crate::output::Output;
use crate::progress::ScanProgress;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 目标IP地址
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let target_ip: IpAddr = args.target.parse()?;
    let timeout = Duration::from_millis(args.timeout);
    let total_ports = (args.end_port - args.start_port + 1) as u64;

    // 解析扫描类型
    let scan_type = match args.scan_type.to_lowercase().as_str() {
        "tcp" => ScanType::Tcp,
        "udp" => ScanType::Udp,
        _ => {
            eprintln!("无效的扫描类型，使用默认值 TCP");
            ScanType::Tcp
        }
    };

    println!("{} 开始{}扫描 {}...", 
        "[*]".blue(), 
        if matches!(scan_type, ScanType::Tcp) { "TCP" } else { "UDP" },
        target_ip
    );

    // 创建进度显示器
    let progress = Arc::new(ScanProgress::new(total_ports));

    // 创建扫描器
    let scanner = Scanner::new(
        target_ip,
        args.start_port,
        args.end_port,
        timeout,
        args.threads,
        progress.clone(),
        scan_type.clone(),
    );

    // 执行端口扫描
    let open_ports = scanner.run().await?;

    // 完成进度显示
    progress.finish();

    // 创建输出对象
    let mut output = Output::new(args.target.clone());

    // 操作系统识别
    let os_detector = OSDetector::new(target_ip);
    if let Ok(os_info) = os_detector.detect().await {
        output.set_os_info(os_info);
    }

    // 服务识别
    for port in open_ports {
        let detector = ServiceDetector::new(target_ip, port, timeout);
        if let Ok(service) = detector.detect() {
            output.add_port(port, service, 
                if matches!(scan_type, ScanType::Tcp) { "TCP" } else { "UDP" }.to_string()
            );
        }
    }

    // 输出结果
    output.print_console();

    // 保存结果
    if let Some(path) = args.json_output {
        output.save_json(&path)?;
        println!("{} 结果已保存到: {:?}", "[*]".blue(), path);
    }

    if let Some(path) = args.csv_output {
        output.save_csv(&path)?;
        println!("{} 结果已保存到: {:?}", "[*]".blue(), path);
    }

    Ok(())
}