use std::fmt::Debug;


// 参数，输出相关
#[derive(Debug)]
pub struct OutArg {
    // 输出形式
    pub out_type: OutType,
    // 输出数据层
    pub out_pro: OutPro,
    // 协议控制
    pub pro_arg: Box<dyn ProArg>,
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
            pro_arg: Box::new(ProArgNone),
            file_name: None,
            pcap_file_name: None,
        }
    }

    // 使用指定的ProArg生成OutArg
    pub fn new_with_pro_arg(pro_arg: Box<dyn ProArg>) -> OutArg {
        OutArg {
            out_type: OutType::Text("utf8"),
            out_pro: OutPro::Application,
            pro_arg,
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
    // 16进制
    Hexadecimal,
    // 文本，.0是编码，目前不使用
    Text(&'static str),
}

impl OutType {
    pub fn from_name(name: &str) -> Option<OutType> {
        match name {
            "itself" => Some(OutType::Itself),
            "decimal" => Some(OutType::Decimal),
            "hexadecimal" => Some(OutType::Hexadecimal),
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
    pub fn from_name(name: &str) -> Option<OutPro> {
        match name {
            "link" => Some(OutPro::Link),
            "network" => Some(OutPro::Network),
            "transport" => Some(OutPro::Transport),
            "application" => Some(OutPro::Application),
            _ => None,
        }
    }
}

pub trait ProArg: Debug {
    // 原始字节处理
    fn original_byte_process<'a>(&self, data: &'a[u8]) -> &'a[u8];
    // 转换后的字节处理
    fn trans_byte_process<'a>(&self, data: &'a[u8]) -> &'a[u8];
}

// 无协议控制
#[derive(Debug)]
struct ProArgNone;

impl ProArg for ProArgNone {
    fn original_byte_process<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        data
    }
    fn trans_byte_process<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        data
    }
}
