use std::collections::HashMap;

use crate::{process::{OutPro, OutType}, DumpError, FilterArg, OutArg};

type ArgAnalyze = fn(&Vec<String>, usize, &mut FilterArg, &mut OutArg) -> Result<usize, DumpError>;

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
    _: &mut OutArg,
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
