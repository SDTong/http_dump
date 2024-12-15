fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        show_print();
        return;
    }
    let dump_arg = http_dump::dump_arg::read_arg(args);
    match dump_arg {
        Ok((filter_arg, out_arg)) => http_dump::start(filter_arg, out_arg),
        Err(error) => println!("{}", error),
    }
}

// 显示参数说明，就是 help
fn show_print() {
    let help = r#"
-h --help       显示帮助
-i              网口
-r              从读文件读取网络数据
-w              生成pcap文件。文件格式同tcpdump命令-w参数生成的文件。不受-op、-ot等输出相关参数控制
-p --port       端口号
-op --outPro    输出协议层，支持值域：link(链路层), network(网络层), transport(传输层), application(应用层)，默认值： application
-ot --outType   输出类型，支持值域：itself(原值), decimal(10进制数组), text(utf8编码的字符串)，默认值：text
"#;
    print!("{help}");
}
