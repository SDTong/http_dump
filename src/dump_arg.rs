use std::{collections::HashMap, path::PathBuf};

use crate::{analyze, DumpError};


type ArgAnalyze =
    fn(&Vec<String>, usize, &mut FilterArg, &mut OutArg) -> Result<usize, DumpError>;

// 参数，过滤相关
#[derive(Debug)]
pub struct FilterArg {
    // 网口名，比如常见的en0、lo0（环回地址）
    // 默认值：any 表示所有网口
    pub device_name: String,
    // 从文件读取数据，优先级高于网口
    pub file_name: Option<PathBuf>,
    // 网络层协议，IP什么的
    pub net_pro: Option<String>,
    // 传输层协议，TCP什么的
    pub tran_pro: Option<String>,
    // 应用层协议，HTTP什么的
    pub application_pro: Option<analyze::ApplicationPro>,
    pub port: Option<u16>,
    pub timeout: i32,
}

impl FilterArg {
    fn new() -> FilterArg {
        let filter_arg = FilterArg {
            device_name: "any".to_string(),
            file_name: None,
            net_pro: Some("ip".to_string()),
            tran_pro: Some("tcp".to_string()),
            application_pro: Some(analyze::ApplicationPro::HTTP),
            port: Some(80),
            timeout: 200,
        };
        filter_arg
    }
}

// 参数，输出相关
#[derive(Debug)]
pub struct OutArg {
    // 输出形式
    pub out_type: OutType,
    // 输出位置，true：文件，false：控制台
    pub file_flag: bool,
    // 文件名，当输出到文件时，预期有值
    pub file_name: Option<String>,
}

// 输出形式
#[derive(Debug)]
pub enum OutType {
    // 原值
    Itself,
    // 10进制
    Decimal,
    // 文本，.0是编码，目前不使用
    Text(&'static str),
}

impl OutType {
    fn from_name(name: &str) -> Option<OutType> {
        match name {
            "itself" => Some(OutType::Itself),
            "decimal" => Some(OutType::Decimal),
            "text" => Some(OutType::Text("utf8")),
            _ => None,
        }
    }
}

impl OutArg {
    fn new() -> OutArg {
        OutArg {
            out_type: OutType::Text("utf8"),
            file_flag: false,
            file_name: None,
        }
    }
}

pub fn read_arg(args: Vec<String>) -> Result<(FilterArg, OutArg), DumpError> {
    let mut filter_arg= FilterArg::new();
    let mut out_arg = OutArg::new();

    let analyze_map = all_analyze_fn();

    let mut index = 0;
    while index < args.len() {
        let key = args[index].as_str();
        if let Some(analyze_fn) = analyze_map.get(key) {
            index = analyze_fn(&args, index, &mut filter_arg, &mut out_arg)?;
        } else {
            index += 1;
        }
    }

    Ok((filter_arg, out_arg))
}

// 获取所有处理函数
fn all_analyze_fn() -> HashMap<&'static str, ArgAnalyze> {
    let mut map: HashMap<&str, ArgAnalyze> = HashMap::new();
    map.insert("-i", device_name_analy);
    map.insert("-r", file_name_analy);
    map.insert("-p", port_analy);
    map.insert("--port", port_analy);
    map.insert("-ot", out_type_analy);
    map.insert("--outType", out_type_analy);

    map
}

// 网口 -i
fn device_name_analy(
    args: &Vec<String>,
    index: usize,
    filter_arg: &mut FilterArg,
    _out_arg: &mut OutArg,
) -> Result<usize, DumpError> {
    if args.len() <= index + 1 {
        // 正常是 -p 80 或 -port 80 ，少了值
        return Err(DumpError {
            msg: "网口缺少值".to_string(),
        });
    }
    let index = index + 1;
    filter_arg.device_name = args[index].clone();
    
    Ok(index + 1)
}

// 从pcap文件读取数据
fn file_name_analy(
    args: &Vec<String>,
    index: usize,
    filter_arg: &mut FilterArg,
    _out_arg: &mut OutArg,
) -> Result<usize, DumpError> {
    if args.len() <= index + 1 {
        // 正常是 -r 文件名 ，少了值
        return Err(DumpError {
            msg: "缺少文件名".to_string(),
        });
    }
    let index = index + 1;
    filter_arg.file_name = Some(args[index].clone().into());
    
    Ok(index + 1)
}

// port -p --port
fn port_analy(
    args: &Vec<String>,
    index: usize,
    filter_arg: &mut FilterArg,
    _out_arg: &mut OutArg,
) -> Result<usize, DumpError> {
    if args.len() <= index + 1 {
        // 正常是 -p 80 或 -port 80 ，少了值
        return Err(DumpError {
            msg: "端口号缺少值".to_string(),
        });
    }
    let index = index + 1;
    let port = args[index].parse();
    if port.is_err() {
        return Err(DumpError {
            msg: "端口号错误，仅支持0-65535".to_string(),
        });
    }
    filter_arg.port = Some(port.unwrap());

    Ok(index + 1)
}

// 输出类型 -ot --outType
fn out_type_analy(
    args: &Vec<String>,
    index: usize,
    _filter_arg: &mut FilterArg,
    out_arg: &mut OutArg,
) -> Result<usize, DumpError> {
    if args.len() <= index + 1 {
        // 正常是 -ot text 或 --port text ，少了值
        return Err(DumpError {
            msg: "输出类型缺少值".to_string(),
        });
    }
    let index = index + 1;
    match OutType::from_name(&args[index]) {
        Some(out_type) => out_arg.out_type = out_type,
        None => return Err(DumpError {
            msg: "不支持的输出类型".to_string(),
        }),
    }

    Ok(index + 1)
}
