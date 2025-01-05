use std::sync::mpsc::Receiver;

pub use out_arg::{OutArg, OutPro, OutType};

use crate::PacketInfo;

// 输出控制参数
mod out_arg;
// 获取协议数据
mod get_pro_data;
// 数据转换
mod change_data;
// 输出数据
mod out_data;

pub fn process(out_arg: OutArg, receiver: &Receiver<PacketInfo>) {
    if out_arg.pcap_file_name.is_some() {
        for _ in receiver {}
        return;
    }
    let get_pro_data = get_pro_data::get_data_fn(&out_arg.out_pro);
    let change_data = change_data::change_data_fn(&out_arg.out_type);
    let out_data = out_data::out_data_fn(&out_arg);

    for packet_info in receiver {
        let data = get_pro_data(&packet_info);
        let data = change_data(data);
        out_data(&data);
        out_data(b"\n\n");
    }
}
