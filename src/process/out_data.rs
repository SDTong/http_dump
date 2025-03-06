use std::{fs::File, io::Write};

use super::OutArg;

// 获取文件句柄
pub fn get_file_handle(out_arg: &OutArg) -> Option<File> {
    out_arg.out_file.as_ref().map(|out_file| File::create(out_file).unwrap())
}

// 数据输出
pub fn out_data_fn(out_arg: &OutArg) -> impl Fn(&[u8], &mut Option<File>) {
    if let Some(_) = &out_arg.out_file {
        write_file_data
    } else {
        println_console_data
    }
}

// 处理报文
// 输出到控制台
fn println_console_data(data: &[u8], _out_file: &mut Option<File>) {
    if data.is_empty() {
        return;
    }
    let mut out = std::io::stdout().lock();
    out.write_all(data).unwrap();
}

// 输出到文件
fn write_file_data(data: &[u8], out_file: &mut Option<File>) {
    out_file.as_mut().unwrap().write_all(data).unwrap();
}
