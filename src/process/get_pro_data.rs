use crate::PacketInfo;

use super::out_arg;



// 获取基础数据
pub(crate) fn get_data_fn(out_pro: &out_arg::OutPro) -> fn(&PacketInfo) -> &[u8] {
    match out_pro {
        out_arg::OutPro::Link => link_pro_data,
        out_arg::OutPro::Network => network_pro_data,
        out_arg::OutPro::Transport => transport_pro_data,
        out_arg::OutPro::Application => application_pro_data,
    }
}

// 链路层报文
fn link_pro_data(packet_info: &PacketInfo) -> &[u8] {
    &packet_info.data[packet_info.pro_type.link_start..]
}

// 网络层报文
fn network_pro_data(packet_info: &PacketInfo) -> &[u8] {
    &packet_info.data[packet_info.pro_type.network_start..]
}

// 传输层报文
fn transport_pro_data(packet_info: &PacketInfo) -> &[u8] {
    &packet_info.data[packet_info.pro_type.transport_start..]
}

// 应用层报文
fn application_pro_data(packet_info: &PacketInfo) -> &[u8] {
    &packet_info.data[packet_info.pro_type.application_start..]
}
