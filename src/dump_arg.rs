use std::{collections::HashMap, fmt::Debug, path::PathBuf};

use crate::{analyze, DumpError};

type ArgAnalyze = fn(&Vec<String>, usize, &mut FilterArg, &mut OutArg) -> Result<usize, DumpError>;

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
            application_pro: None,
            port: Some(80),
            bpf: None,
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
    // 输出数据层
    pub out_pro: OutPro,
    // 文件名，有值时，输出到文件，没有值时，输出到控制台
    pub file_name: Option<String>,
    // pcap文件名，和tcpdump -w命令相同
    pub pcap_file_name: Option<String>,
}

impl OutArg {
    pub fn new() -> OutArg {
        OutArg {
            out_type: OutType::Text("utf8"),
            out_pro: OutPro::Application,
            file_name: None,
            pcap_file_name: None,
        }
    }
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

// 输出协议，包含协议头
#[derive(Debug)]
pub enum OutPro {
    Link,
    Network,
    Transport,
    Application,
}

impl OutPro {
    fn from_name(name: &str) -> Option<OutPro> {
        match name {
            "link" => Some(OutPro::Link),
            "network" => Some(OutPro::Network),
            "transport" => Some(OutPro::Transport),
            "application" => Some(OutPro::Application),
            _ => None,
        }
    }
}

pub fn read_arg(args: Vec<String>) -> Result<(FilterArg, OutArg), DumpError> {
    let mut filter_arg = FilterArg::new();
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
    map.insert("-r", in_file_name_analy);
    map.insert("-w", pcap_file_name_analy);
    map.insert("-p", port_analy);
    map.insert("--port", port_analy);
    map.insert("--bpf", bpf_analy);
    map.insert("-ot", out_type_analy);
    map.insert("--outType", out_type_analy);
    map.insert("-op", out_pro_analy);
    map.insert("--outPro", out_pro_analy);

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
fn in_file_name_analy(
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

// BPF过滤条件
fn bpf_analy(
    args: &Vec<String>,
    index: usize,
    filter_arg: &mut FilterArg,
    _out_arg: &mut OutArg,
) -> Result<usize, DumpError> {
    if args.len() <= index + 1 {
        // 正常是 --bpf 'host 127.0.0.1' ，少了值
        return Err(DumpError {
            msg: "BPF过滤条件缺少值".to_string(),
        });
    }
    let index = index + 1;
    filter_arg.bpf = Some(args[index].clone());

    Ok(index + 1)
}

// 输出协议层 -op --outPro
fn out_pro_analy(
    args: &Vec<String>,
    index: usize,
    _filter_arg: &mut FilterArg,
    out_arg: &mut OutArg,
) -> Result<usize, DumpError> {
    if args.len() <= index + 1 {
        // 正常是 -ot text 或 --port text ，少了值
        return Err(DumpError {
            msg: "输出协议层缺少值".to_string(),
        });
    }
    let index = index + 1;
    match OutPro::from_name(&args[index]) {
        Some(out_pro) => out_arg.out_pro = out_pro,
        None => {
            return Err(DumpError {
                msg: "不支持的输出协议层".to_string(),
            })
        }
    }

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
        None => {
            return Err(DumpError {
                msg: "不支持的输出类型".to_string(),
            })
        }
    }

    Ok(index + 1)
}

// 生成pcap文件 -w
fn pcap_file_name_analy(
    args: &Vec<String>,
    index: usize,
    _filter_arg: &mut FilterArg,
    out_arg: &mut OutArg,
) -> Result<usize, DumpError> {
    if args.len() <= index + 1 {
        // 正常是 -w 文件名 ，少了值
        return Err(DumpError {
            msg: "缺少pcap文件名".to_string(),
        });
    }
    let index = index + 1;
    out_arg.pcap_file_name = Some(args[index].clone());

    Ok(index + 1)
}
