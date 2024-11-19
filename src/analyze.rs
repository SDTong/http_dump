use std::mem;

const LOOPBACK_ADDRESS_START: [u8; 4] = [2, 0, 0, 0];

// 协议类型
#[derive(Debug)]
pub struct ProType {
    link_pro: LinkPro,
    link_start: usize,
    link_head_len: usize,
    network_pro: NetworkPro,
    network_start: usize,
    network_head_len: usize,
    pub transport_pro: TransportPro,
    pub transport_start: usize,
    pub transport_head_len: usize,
    pub application_pro: ApplicationPro,
    pub application_start: usize,
    pub application_head_len: usize,
}

impl From<&[u8]> for ProType {
    fn from(data: &[u8]) -> Self {
        if data.is_empty() {
            return ProType {
                link_pro: LinkPro::Unsupported,
                link_start: 0,
                link_head_len: 0,
                network_pro: NetworkPro::Unsupported,
                network_start: 0,
                network_head_len: 0,
                transport_pro: TransportPro::Unsupported,
                transport_start: 0,
                transport_head_len: 0,
                application_pro: ApplicationPro::Unsupported,
                application_start: 0,
                application_head_len: 0,
            };
        }
        let mut pro_type = mem::MaybeUninit::<ProType>::uninit();

        unsafe {
            analyze_link(pro_type.as_mut_ptr(), data);
            analyze_network(pro_type.as_mut_ptr(), data);
            analyze_transport(pro_type.as_mut_ptr(), data);
            analyze_application(pro_type.as_mut_ptr(), data);
            return pro_type.assume_init();
        }
    }
}

// 链路层协议
#[derive(Debug)]
enum LinkPro {
    // 环回地址
    LoopbackAddress,
    // 以太网
    // Ethernet,
    // 不支持的
    Unsupported,
}

// 网络层协议
#[derive(Debug)]
enum NetworkPro {
    // IPv4
    IPv4,
    // 不支持的
    Unsupported,
}

// 传输层协议
#[derive(Debug)]
pub enum TransportPro {
    TCP,
    // 不支持的
    Unsupported,
}

// 应用层协议
#[derive(Debug, PartialEq, Eq)]
pub enum ApplicationPro {
    HTTP,
    // 不支持的
    Unsupported,
}

// 分析链路层协议
unsafe fn analyze_link(pro_type: *mut ProType, data: &[u8]) {
    if data.len() >= 4 && data.starts_with(&LOOPBACK_ADDRESS_START) {
        // 环回地址
        (*pro_type).link_pro = LinkPro::LoopbackAddress;
        (*pro_type).link_start = 0;
        (*pro_type).link_head_len = LOOPBACK_ADDRESS_START.len();
    }
    // 未知协议
    (*pro_type).link_pro = LinkPro::Unsupported;
    (*pro_type).link_start = 0;
    (*pro_type).link_head_len = 0;
}

// 分析网络层协议
unsafe fn analyze_network(pro_type: *mut ProType, data: &[u8]) {
    match (*pro_type).link_pro {
        LinkPro::LoopbackAddress => {
            // 链路层没有记录协议，只要可以识别为IP，就认为是IP，复杂的以后再说
            let start = (*pro_type).link_start + (*pro_type).link_head_len;
            if data.len() >= start && guess_ipv4(pro_type, start, data) {
                return;
            }
        }
        LinkPro::Unsupported => {
            // 发现访问127.0.0.1时，可能没有链路层协议，
            // 只要可以识别为IP，就认为是IP，复杂的以后再说
            let start = (*pro_type).link_start + (*pro_type).link_head_len;
            if data.len() >= start && guess_ipv4(pro_type, start, data) {
                return;
            }
        }
    }
    (*pro_type).network_pro = NetworkPro::Unsupported;
    (*pro_type).network_start = if let LinkPro::Unsupported = (*pro_type).link_pro {
        (*pro_type).link_start
    } else {
        (*pro_type).link_start + (*pro_type).link_head_len
    };
    (*pro_type).network_head_len = 0;
}

// 猜测是否为ipv4，
// 只要可以识别为IP，就认为是IP，复杂的以后再说
unsafe fn guess_ipv4(pro_type: *mut ProType, start: usize, data: &[u8]) -> bool {
    if data[start + 0] >> 4 != 4 {
        return false;
    }
    let head_len = (data[start + 0] & 0b00001111) * 4;
    if data.len() < head_len as usize {
        return false;
    }
    (*pro_type).network_pro = NetworkPro::IPv4;
    (*pro_type).network_start = start;
    (*pro_type).network_head_len = head_len as usize;
    true
}

// 分析传输层协议
unsafe fn analyze_transport(pro_type: *mut ProType, data: &[u8]) {
    if let NetworkPro::IPv4 = (*pro_type).network_pro {
        (*pro_type).transport_start = (*pro_type).network_start + (*pro_type).network_head_len;
        if data[(*pro_type).network_start + 9] == 0x06
            && data.len() >= (*pro_type).transport_start + 20
        {
            (*pro_type).transport_pro = TransportPro::TCP;
            (*pro_type).transport_head_len =
                (data[(*pro_type).transport_start + 12] >> 4) as usize * 4;
            return;
        }
    }
    (*pro_type).transport_pro = TransportPro::Unsupported;
    (*pro_type).transport_start = if let NetworkPro::Unsupported = (*pro_type).network_pro {
        (*pro_type).network_start
    } else {
        (*pro_type).network_start + (*pro_type).network_head_len
    };
    (*pro_type).transport_head_len = 0;
}

// 分析应用层协议
unsafe fn analyze_application(pro_type: *mut ProType, data: &[u8]) {
    let start = (*pro_type).transport_start + (*pro_type).transport_head_len;
    (*pro_type).application_start = start;
    let payload = &data[start..];
    if payload.starts_with(b"GET")
        || payload.starts_with(b"POST")
        || payload.starts_with(b"PUT")
        || payload.starts_with(b"DELETE")
        || payload.starts_with(b"HEAD")
        || payload.starts_with(b"OPTIONS")
        || payload.starts_with(b"PATCH")
        || payload.starts_with(b"CONNECT")
        || payload.starts_with(b"TRACE")
        || payload.starts_with(b"HTTP")
    {
        (*pro_type).application_pro = ApplicationPro::HTTP;
        (*pro_type).application_head_len = 0;
        return;
    }

    (*pro_type).application_pro = ApplicationPro::Unsupported;
    (*pro_type).application_head_len = 0;
}
