use std::collections::HashMap;

use crate::{process::ProArgHttp, DumpError};

type HttpArgAnalyze = fn(&Vec<String>, usize, &mut ProArgHttp) -> Result<usize, DumpError>;

// 读取http协议控
pub(super) fn read_arg(args: &Vec<String>) -> Result<Box<ProArgHttp>, DumpError> {
    let mut pro_arg = Box::new(ProArgHttp::new());
    let analyze_map = all_analyze_fn();

    let mut index = 0;
    while index < args.len() {
        let key = args[index].as_str();
        if let Some(analyze_fn) = analyze_map.get(key) {
            index = analyze_fn(&args, index, &mut pro_arg)?;
        } else {
            index += 1;
        }
    }

    Ok(pro_arg)
}

// 获取所有处理函数
fn all_analyze_fn() -> HashMap<&'static str, HttpArgAnalyze> {
    let mut map: HashMap<&str, HttpArgAnalyze> = HashMap::new();
    map.insert("-http.hh", hide_head_analy);
    map.insert("--http.hideHead", hide_head_analy);
    map.insert("-http.hb", hide_body_analy);
    map.insert("--http.hideBody", hide_body_analy);
    map.insert("-http.it", out_itself_analy);
    map.insert("--http.itself", out_itself_analy);

    map
}

// 隐藏http头 -http.hh  --http.hideHead
fn hide_head_analy(
    _args: &Vec<String>,
    index: usize,
    pro_arg: &mut ProArgHttp,
) -> Result<usize, DumpError> {
    pro_arg.head_show = false;
    Ok(index + 1)
}

// 隐藏http体 -http.hb --http.hideBody
fn hide_body_analy(
    _args: &Vec<String>,
    index: usize,
    pro_arg: &mut ProArgHttp,
) -> Result<usize, DumpError> {
    pro_arg.body_show = false;
    Ok(index + 1)
}

// 输出数组 -http.it --http.itself  
fn out_itself_analy(
    _args: &Vec<String>,
    index: usize,
    pro_arg: &mut ProArgHttp,
) -> Result<usize, DumpError> {
    pro_arg.itself = true;
    Ok(index + 1)
}

