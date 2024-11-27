use crate::{analyze, DumpError};

type ArgAnalyze =
    fn(&Vec<String>, usize, &mut FilterArg, &mut OutArg) -> Result<(bool, usize), DumpError>;

static ARG_ANALYZE_ARRAY: [ArgAnalyze; 2] = [port_analy, help_analy];

// 参数，过滤相关
#[derive(Debug)]
pub struct FilterArg {
    // 网口名，比如常见的en0、lo0（环回地址）
    // 默认值：any 表示所有网口
    pub device_name: String,
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
        FilterArg {
            device_name: "any".to_string(),
            net_pro: None,
            tran_pro: None,
            application_pro: None,
            port: None,
            timeout: 200,
        }
    }

    fn default_arg() -> Self {
        Self {
            device_name: "any".to_string(),
            net_pro: Some("ip".to_string()),
            tran_pro: Some("tcp".to_string()),
            application_pro: Some(analyze::ApplicationPro::HTTP),
            port: Some(80),
            timeout: 200,
        }
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

impl OutArg {
    fn new() -> OutArg {
        OutArg {
            out_type: OutType::Decimal,
            file_flag: false,
            file_name: None,
        }
    }

    fn default_arg() -> Self {
        Self {
            out_type: OutType::Text("utf8"),
            file_flag: false,
            file_name: None,
        }
    }
}

pub fn read_arg(args: Vec<String>) -> Result<(FilterArg, OutArg), DumpError> {
    // 检查是否使用默认值
    let mut filter_arg;
    let mut out_arg;
    if args.contains(&"-d".to_string()) || args.contains(&"--default".to_string()) {
        filter_arg = FilterArg::default_arg();
        out_arg = OutArg::default_arg();
    } else {
        filter_arg = FilterArg::new();
        out_arg = OutArg::new();
    };

    let mut index = 0;
    while index < args.len() {
        for analyze_fn in ARG_ANALYZE_ARRAY {
            let (next_flag, next_index) = analyze_fn(&args, index, &mut filter_arg, &mut out_arg)?;
            index = next_index;
            if !next_flag {
                break;
            }
        }
    }

    Ok((filter_arg, out_arg))
}

// help
fn help_analy(
    _args: &Vec<String>,
    index: usize,
    _filter_arg: &mut FilterArg,
    _out_arg: &mut OutArg,
) -> Result<(bool, usize), DumpError> {
    Ok((true, index + 1))
}

// port
fn port_analy(
    args: &Vec<String>,
    index: usize,
    filter_arg: &mut FilterArg,
    _out_arg: &mut OutArg,
) -> Result<(bool, usize), DumpError> {
    if args.len() <= index {
        return Ok((false, index));
    }
    if "-p" != args[index] && "-port" != args[index] {
        return Ok((true, index));
    }
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
            msg: "端口号错误，仅支持0-255".to_string(),
        });
    }
    filter_arg.port = Some(port.unwrap());

    Ok((false, index + 1))
}
