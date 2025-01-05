use std::path::PathBuf;

use crate::analyze;


// 参数，过滤相关
#[derive(Debug)]
pub struct FilterArg {
    // 网口名，比如常见的en0、lo0（环回地址）
    // 默认值：any 表示所有网口
    pub device_name: String,
    // 从文件读取数据，优先级高于网口
    pub file_name: Option<PathBuf>,
    // 应用层协议，HTTP什么的
    pub application_pro: Option<analyze::ApplicationPro>,
    pub port: Option<u16>,
    // BPF过滤条件
    pub bpf: Option<String>,
    pub timeout: i32,
}

impl FilterArg {
    pub fn new() -> FilterArg {
        let filter_arg = FilterArg {
            device_name: "any".to_string(),
            file_name: None,
            application_pro: Some(analyze::ApplicationPro::HTTP),
            port: Some(80),
            bpf: None,
            timeout: 200,
        };
        filter_arg
    }
}
