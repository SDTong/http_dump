use std::{
    borrow::Cow, io::Write, sync::mpsc::{self, Sender}, thread
};

use crate::{dump_arg, OutArg, PacketInfo};

pub fn process(out_arg: &OutArg) -> Sender<PacketInfo> {
    let get_data = get_data_fn(out_arg);
    let change_data = change_data_fn(out_arg);
    let out_data = out_data_fn(out_arg);
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        for packet_info in receiver {
            let data = get_data(&packet_info);
            let data = change_data(data);
            out_data(&data);
            out_data(b"\n\n");
        }
    });
    sender
}

// 获取基础数据
fn get_data_fn(_out_arg: &OutArg) -> fn(&PacketInfo) -> &[u8] {
    application_all_data
}

// 数据转换
fn change_data_fn(out_arg: &OutArg) -> fn(&[u8]) -> Cow<'_, [u8]> {
    match out_arg.out_type {
        dump_arg::OutType::Decimal => u8_array,
        dump_arg::OutType::Text(_) => u8_to_str,
        _ => |x| Cow::Borrowed(x),
    }
}

// 数据输出
fn out_data_fn(out_arg: &OutArg) -> fn(&[u8]) {
    if out_arg.file_flag {
        write_file_data
    } else {
        println_console_data
    }
}

// 应用层报文
fn application_all_data(packet_info: &PacketInfo) -> &[u8] {
    &packet_info.data[packet_info.pro_type.application_start..]
}

// 转成str，目前仅支持utf8
fn u8_to_str(data: &[u8]) -> Cow<'_, [u8]> {
    Cow::Owned(String::from_utf8_lossy(data).into_owned().into_bytes())
}
// 输出数组，10进制
fn u8_array(data: &[u8]) -> Cow<'_, [u8]> {
    let data = format!("{:?}", data);
    Cow::Owned(data.into_bytes())
}

// 处理报文
// 输出到控制台
fn println_console_data(data: &[u8]) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(data);
}

// 输出到文件
fn write_file_data(_data: &[u8]) {
    todo!()
}
