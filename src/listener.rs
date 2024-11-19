use std::sync::mpsc::Sender;

use pcap::{Active, Capture, Device};

use crate::{analyze, FilterArg, PacketInfo};

pub fn listener(filter_arg: &FilterArg, sender: Sender<PacketInfo>) {
    let device = Device::from(filter_arg.device_name.as_str());
    let device_name = device.name.clone();
    let mut capture = get_capture(device, &filter_arg);
    set_filter(&filter_arg, &mut capture);
    println!("device name: {device_name} start");
    listening(&filter_arg, capture, sender);
}

// 获取 Capture
// 就是操作句柄
fn get_capture(device: Device, filter_arg: &FilterArg) -> Capture<Active> {
    pcap::Capture::from_device(device)
        .unwrap()
        // 设置混杂模式，支持接收所有网络端口的数据
        // .promisc(true)
        // 实时
        // .immediate_mode(true)
        // 超时
        .timeout(filter_arg.timeout)
        .open()
        .unwrap()
}

// 设置过滤器
fn set_filter(filter_arg: &FilterArg, capture: &mut Capture<Active>) {
    // capture.filter("port 8088", true).unwrap();
    let mut program = String::new();
    if let Some(net_pro) = &filter_arg.net_pro {
        program.push_str(net_pro);
        program.push_str(" and ");
    }
    if let Some(tran_pro) = &filter_arg.tran_pro {
        program.push_str(tran_pro);
        program.push_str(" and ");
    }
    if let Some(port) = filter_arg.port {
        program.push_str("port ");
        program.push_str(&port.to_string());
        program.push_str(" and ");
    }
    if let Some(program) = program.strip_suffix(" and ") {
        capture.filter(program, true).unwrap();
    } else if !program.is_empty() {
        capture.filter(&program, true).unwrap();
    }
}

// 开启监听
fn listening(filter_arg: &FilterArg, mut capture: Capture<Active>, sender: Sender<PacketInfo>) {
    loop {
        match capture.next_packet() {
            Ok(packet) => {
                let pro_type = analyze::ProType::from(packet.data);
                if !filter(filter_arg, &pro_type) {
                    // 不是目标
                    continue;
                }
                let packet_info = PacketInfo {
                    pro_type,
                    data: Vec::from(packet.data),
                };
                if let Err(_) = sender.send(packet_info) {
                    break;
                }
            }
            Err(error) if pcap::Error::TimeoutExpired == error => {
                // 超时错误，忽略
            }
            Err(error) => {
                println!("发生异常: {error}");
                break;
            }
        }
    }
}

// 进一步自定义过滤
fn filter(filter_arg: &FilterArg, pro_type: &analyze::ProType) -> bool {
    if let Some(application_pro) = &filter_arg.application_pro {
        if *application_pro != pro_type.application_pro {
            return false;
        }
    }

    true
}
