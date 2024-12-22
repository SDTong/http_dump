use std::mem;

// mac os 下，环回地址报文开头，不再通过报文判断
const LOOPBACK_ADDRESS_START: [u8; 4] = [2, 0, 0, 0];

// 协议类型
#[derive(Debug)]
pub struct ProType {
    link_pro: LinkPro,
    pub link_start: usize,
    link_head_len: usize,
    network_pro: NetworkPro,
    pub network_start: usize,
    network_head_len: usize,
    pub transport_pro: TransportPro,
    pub transport_start: usize,
    pub transport_head_len: usize,
    pub application_pro: ApplicationPro,
    pub application_start: usize,
}

impl ProType {
    pub(crate) fn from_with_linktype(linktype: &pcap::Linktype, data: &[u8]) -> Self {
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
            };
        }
        let mut pro_type = mem::MaybeUninit::<ProType>::uninit();

        unsafe {
            analyze_link_with_linktype(linktype, pro_type.as_mut_ptr(), data);
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
    // 无，一般是监听any，这时没有链路层数据
    NotHave,
    // 环回地址
    LoopbackAddress,
    // 以太网
    Ethernet,
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
unsafe fn analyze_link_with_linktype(
    linktype: &pcap::Linktype,
    pro_type: *mut ProType,
    _data: &[u8],
) {
    if *linktype == pcap::Linktype::NULL {
        // 环回地址
        (*pro_type).link_pro = LinkPro::LoopbackAddress;
        (*pro_type).link_start = 0;
        (*pro_type).link_head_len = LOOPBACK_ADDRESS_START.len();
        return;
    }
    match linktype.0 {
        1 => {
            // 以太网
            (*pro_type).link_pro = LinkPro::Ethernet;
            (*pro_type).link_start = 0;
            (*pro_type).link_head_len = 14;
        }
        12 => {
            // mac os下，监听any网口，没有数据链路层
            (*pro_type).link_pro = LinkPro::NotHave;
            (*pro_type).link_start = 0;
            (*pro_type).link_head_len = 0;
        }
        _ => {
            // 未知协议
            (*pro_type).link_pro = LinkPro::Unsupported;
            (*pro_type).link_start = 0;
            (*pro_type).link_head_len = 0;
        }
    }
}

// 分析网络层协议
unsafe fn analyze_network(pro_type: *mut ProType, data: &[u8]) {
    match (*pro_type).link_pro {
        LinkPro::Ethernet => {
            analyze_network_from_ethernet(pro_type, data);
        }
        LinkPro::NotHave | LinkPro::LoopbackAddress => {
            // 只要可以识别为IP，就认为是IP，复杂的以后再说
            // 链路层没有记录协议，只要可以识别为IP，就认为是IP，复杂的以后再说
            let start = (*pro_type).link_start + (*pro_type).link_head_len;
            if !guess_ipv4(pro_type, start, data) {
                (*pro_type).network_pro = NetworkPro::Unsupported;
                (*pro_type).network_start = if let LinkPro::Unsupported = (*pro_type).link_pro {
                    (*pro_type).link_start
                } else {
                    (*pro_type).link_start + (*pro_type).link_head_len
                };
                (*pro_type).network_head_len = 0;
            }
        }
        _ => {
            (*pro_type).network_pro = NetworkPro::Unsupported;
            (*pro_type).network_start = if let LinkPro::Unsupported = (*pro_type).link_pro {
                (*pro_type).link_start
            } else {
                (*pro_type).link_start + (*pro_type).link_head_len
            };
            (*pro_type).network_head_len = 0;
        }
    }
}

// 根据以太网帧，分析网络层协议信息
unsafe fn analyze_network_from_ethernet(pro_type: *mut ProType, data: &[u8]) {
    let link_start = (*pro_type).link_start;
    let link_head_len = (*pro_type).link_head_len;
    (*pro_type).network_start = link_start + link_head_len;
    let most = data[link_start + 12] as u16;
    let least = data[link_start + 13] as u16;
    let pro = most << 8 | least;

    match pro {
        0x0800 => {
            // IPv4
            let head_len = (data[(*pro_type).network_start + 0] & 0x0F) * 4;
            (*pro_type).network_pro = NetworkPro::IPv4;
            (*pro_type).network_head_len = head_len as usize;
        }
        _ => {
            (*pro_type).network_pro = NetworkPro::Unsupported;
            (*pro_type).network_head_len = 0;
        }
    }
}

// 猜测是否为ipv4，
// 只要可以识别为IP，就认为是IP，复杂的以后再说
unsafe fn guess_ipv4(pro_type: *mut ProType, start: usize, data: &[u8]) -> bool {
    if data.len() < start {
        return false;
    }
    if data[start + 0] >> 4 != 4 {
        return false;
    }
    let head_len = (data[start + 0] & 0x0F) * 4;
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
        return;
    }

    (*pro_type).application_pro = ApplicationPro::Unsupported;
}
