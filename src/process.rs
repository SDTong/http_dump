use std::{
    sync::mpsc::{self, Sender},
    thread,
};

use crate::PacketInfo;

pub fn process() -> Sender<PacketInfo> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        for packet_info in receiver {
            process_data(packet_info);
        }
    });
    sender
}

// 处理报文
// 异步处理
fn process_data(packet_info: PacketInfo) {
    let app_data = &packet_info.data[packet_info.pro_type.application_start..];
    println!("{}\n", String::from_utf8_lossy(app_data));
}
