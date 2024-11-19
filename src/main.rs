fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.contains(&"-h".to_string()) || args.contains(&"--help".to_string()) {
        show_print();
        return;
    }
    let dump_arg = http_dump::FilterArg::try_from(args);
    if dump_arg.is_err() {
        println!("{}", dump_arg.unwrap_err());
        return;
    }
    http_dump::start(dump_arg.unwrap());
}

// 显示参数说明，就是 help
fn show_print() {
    let help = r#"
-h --help       显示帮助
-d --default    默认参数。捕获IP、TCP协议，80端口，HTTP报文的数据，输出到控制台
-p --port       端口号
"#;
    print!("{help}");
}
