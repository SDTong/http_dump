use std::{borrow::Cow, collections::HashMap, io::Read as _};

use flate2::read::GzDecoder;

use crate::process::out_arg::ProArg;

// http协议控制
#[derive(Debug)]
pub struct ProArgHttp {
    // 显示http头
    pub head_show: bool,
    // 显示http体
    pub body_show: bool,
    // 是否输出原值
    pub itself: bool,
}

impl ProArgHttp {
    pub fn new() -> Self {
        ProArgHttp {
            head_show: true,
            body_show: true,
            itself: false,
        }
    }

    // 寻找\r\n\r\n
    fn find_sep_index(data: &[u8]) -> usize {
        let index = data
            .windows(4)
            .enumerate()
            .find(|(_, window)| window == b"\r\n\r\n");
        if let Some(index) = index {
            index.0
        } else {
            // 未找到http的请求头和请求体，认为都是请求头
            data.len()
        }
    }

    // 转文本
    // content_type: http请求头，Content-Type: text/html
    // content_encoding: http请求头，Content-Encoding: gzip
    fn u8_to_str<'a>(
        &self,
        content_type: Option<&str>,
        data: &'a [u8],
    ) -> Cow<'a, str> {
        // 尝试从Content-Type中，获取编码
        let _encoding = content_type
            .map(|v| {
                v.rsplit(";")
                    .find_map(|s| s.trim().strip_prefix("charset="))
            })
            // 目前，只考虑支持UTF8编码
            .flatten()
            .unwrap_or("UTF8");

        String::from_utf8_lossy(data)
    }

    // 分块传输合并
    fn combin_data<'a>(head_map: &HashMap<String, String>, data: Cow<'a, [u8]>) -> Cow<'a, [u8]> {
        let transfer_encoding = head_map.get("Transfer-Encoding");
        match transfer_encoding {
            None => return data,
            Some(x) if x == "chunked" => return Self::combin_chunked(data),
            // 不支持的分块传输协议
            _ => return data,
        }
    }

    // Transfer-Encoding:chunked 合并请求体
    fn combin_chunked<'a>(data: Cow<'a, [u8]>) -> Cow<'a, [u8]> {
        // 目前看，拿到的报文不全，
        // 尝试拿到内容
        let index = data
            .windows(2) // 使用 windows(2) 创建一个包含相邻两个字节的迭代器
            .position(|window| window == &[0x0D, 0x0A]); // 找到第一个匹配 &[0x0D, 0x0A] 的窗口
            // .map(|i| &bytes[i + 2..]); // 如果找到匹配，返回剩余的字节数组
        match index {
            None => Cow::from(&[] as &[u8]),
            Some(i) => {
                match data {
                    Cow::Owned(mut d) => Cow::from(d.split_off(i + 2)),
                    Cow::Borrowed(d) => Cow::Borrowed(&d[i + 2..]),
                }
            }
        }
    }

    // 解压
    fn decompress<'a>(head_map: &HashMap<String, String>, data: Cow<'a, [u8]>) -> Cow<'a, [u8]> {
        let content_encoding = head_map.get("Content-Encoding");
        match content_encoding {
            None => return data,
            Some(x) if x == "identity" => return data,
            Some(x) if x == "gzip" => return Self::decompress_gzip(data),
            _ => return Cow::from("不支持的压缩协议".as_bytes()),
        }
    }

    // gzip压缩协议解压
    fn decompress_gzip<'a>(data: Cow<'a, [u8]>) -> Cow<'a, [u8]> {
        dbg!(data.len());
        let mut decoder = GzDecoder::new(data.as_ref());
        let mut decompresse_data = Vec::new();
        let decompress_result = decoder.read_to_end(&mut decompresse_data);
        dbg!(&decompress_result); 
        match decompress_result {
            Ok(_) => Cow::Owned(decompresse_data),
            Err(_) => data,
        }
    }

    // 分析显示内容
    fn analyse_target<'a>(&self, head: Cow<'a, [u8]>, body: Cow<'a, [u8]>) -> Cow<'a, [u8]> {
        if !self.head_show {
            return body;
        }
        if !self.body_show {
            return head;
        }
        let mut vec = Vec::with_capacity(head.len() + body.len());
        vec.extend_from_slice(head.as_ref());
        // 请求头和请求体之间，用\r\n分割
        vec.extend_from_slice("\r\n\r\n".as_bytes());
        vec.extend_from_slice(body.as_ref());
        
        Cow::from(vec)
    }

    // 读请求头
    fn read_head(head_data: &[u8]) -> HashMap<String, String> {
        let mut map = HashMap::new();
        let data_str = String::from_utf8_lossy(head_data);
        data_str
            .as_ref()
            .lines()
            // http协议，首行不是请求头，是请求方法和版本
            .skip(1)
            .filter_map(|s| s.split_once(':'))
            .for_each(|(k, v)| {
                map.insert(k.trim().to_string(), v.trim().to_string());
            });

        map
    }
}

impl ProArg for ProArgHttp {
    fn byte_process<'a>(&self, data: &'a [u8]) -> Cow<'a, [u8]> {
        // 找请求头、响应头
        let head_end = Self::find_sep_index(data);
        let head = &data[0..head_end];
        let head_map = Self::read_head(head);

        let body = if self.body_show && self.itself {
            Cow::Borrowed(&data[head_end + 4..])
        } else if self.body_show && data.len() > head_end + 4 {
            let body_data = Cow::Borrowed(&data[head_end + 4..]);
            // 处理分块传输
            let body_data = Self::combin_data(&head_map, body_data);
            // 解压
            Self::decompress(&head_map, body_data)
        } else {
            Cow::from(&[] as &[u8])
        };

        let target_data = self.analyse_target(Cow::Borrowed(head), body);
        
        if self.itself {
            target_data
        } else {
            let content_type = head_map.get("Content-Type");
            let content_type = content_type.map(|s| s.as_str());
            let data = self.u8_to_str(content_type, &target_data);
            // todo 优化，减少内存拷贝
            match data {
                // 只有源字节数组，是utf8时，才会返回Borrowed，源字节数组来自target_data，
                // 将target_data直接返回，可以避免生命周期问题
                Cow::Borrowed(_) => target_data,
                Cow::Owned(s) => Cow::Owned(s.into_bytes()),
            }
        }
    }
}
