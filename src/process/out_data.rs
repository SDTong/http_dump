use std::io::Write;

use super::OutArg;


// 数据输出
pub fn out_data_fn(out_arg: &OutArg) -> fn(&[u8]) {
    if let Some(_) = out_arg.file_name {
        write_file_data
    } else {
        println_console_data
    }
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
