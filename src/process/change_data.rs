use std::borrow::Cow;

use super::out_arg;

// 数据转换
pub fn change_data_fn(out_arg: &out_arg::OutType) -> fn(&[u8]) -> Cow<'_, [u8]> {
    match out_arg {
        out_arg::OutType::Decimal => u8_array,
        out_arg::OutType::Hexadecimal => u8_to_16,
        out_arg::OutType::Text(_) => u8_to_str,
        _ => |x| Cow::Borrowed(x),
    }
}

// 转成str，目前仅支持utf8
fn u8_to_str(data: &[u8]) -> Cow<'_, [u8]> {
    Cow::Owned(String::from_utf8_lossy(data).into_owned().into_bytes())
}

// 输出数组，10进制
fn u8_array(data: &[u8]) -> Cow<'_, [u8]> {
    let data = format!("{:?}", data);
    Cow::Owned(data.into_bytes())
}

// 输出数组，16进制
fn u8_to_16(data: &[u8]) -> Cow<'_, [u8]> {
    // let data = format!("{:#0X?}", data);
    let data = data.iter()
        .map(|byte| format!("0x{:02X}", byte))
        .collect::<Vec<String>>()
        .join(", ");
    let data = format!("[{data}]");
    Cow::Owned(data.into_bytes())
}
