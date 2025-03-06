use std::{borrow::Cow, fmt::Debug};

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
    pub out_file: Option<String>,
    // pcap文件名，和tcpdump -w命令相同
    pub pcap_file_name: Option<String>,
}

impl OutArg {
    pub fn new() -> OutArg {
        OutArg {
            out_type: OutType::Itself,
            out_pro: OutPro::Application,
            pro_arg: Box::new(ProArgNone),
            out_file: None,
            pcap_file_name: None,
        }
    }

    // 使用指定的ProArg生成OutArg
    pub fn new_with_pro_arg(pro_arg: Box<dyn ProArg>) -> OutArg {
        OutArg {
            out_type: OutType::Itself,
            out_pro: OutPro::Application,
            pro_arg,
            out_file: None,
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
}

impl OutType {
    pub fn from_name(name: &str) -> Option<OutType> {
        match name {
            "itself" => Some(OutType::Itself),
            "decimal" => Some(OutType::Decimal),
            "hexadecimal" => Some(OutType::Hexadecimal),
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
    // 字节处理
    // 会在类型转换前调用
    fn byte_process<'a>(&self, data: &'a [u8]) -> Cow<'a, [u8]>;
}

// 无协议控制
#[derive(Debug)]
struct ProArgNone;

impl ProArg for ProArgNone {
    fn byte_process<'a>(&self, data: &'a [u8]) -> Cow<'a, [u8]> {
        Cow::Borrowed(data)
    }
}
