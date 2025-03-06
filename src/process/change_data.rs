use std::borrow::Cow;

use super::out_arg;

// 数据转换
pub(super) fn change_data_fn(out_arg: &out_arg::OutArg) -> fn(&[u8]) -> Cow<'_, [u8]> {
    match out_arg.out_type {
        out_arg::OutType::Decimal => u8_to_10,
        out_arg::OutType::Hexadecimal => u8_to_16,
        _ => |x| Cow::Borrowed(x),
    }
}

// 输出数组，10进制
pub(crate) fn u8_to_10(data: &[u8]) -> Cow<'_, [u8]> {
    let data = format!("{:?}", data);
    Cow::Owned(data.into_bytes())
}

// 输出数组，16进制
pub(crate) fn u8_to_16(data: &[u8]) -> Cow<'_, [u8]> {
    // let data = format!("{:#0X?}", data);
    let data = data
        .iter()
        .map(|byte| format!("0x{:02X}", byte))
        .collect::<Vec<String>>()
        .join(", ");
    let data = format!("[{data}]");
    Cow::Owned(data.into_bytes())
}
