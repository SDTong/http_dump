// 解析参数
pub mod dump_arg;
// 监听
mod listener;
// 分析协议信息
// 为了支持高级的过滤，在过滤数据前，就会分析协议
// 不要在分析协议的代码里调用耗时长的方法
mod analyze;
// 数据加工
mod process;

use std::{error, fmt};

pub use dump_arg::FilterArg;
pub use dump_arg::OutArg;
// type GenericError = Box<dyn std::error::Error + Send + Sync + 'static>;

// 自定义错误类型
#[derive(Debug, Clone)]
pub struct DumpError {
    msg: String,
}

impl fmt::Display for DumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl error::Error for DumpError {}

#[derive(Debug)]
pub struct PacketInfo {
    pro_type: analyze::ProType,
    data: Vec<u8>,
}

// 入口
pub fn start(filter_arg: FilterArg, out_arg: OutArg) {
    let sender = process::process(&out_arg);
    listener::listener(&filter_arg, sender);
}
