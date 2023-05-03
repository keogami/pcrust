use pcap::Packet;

pub struct Codec {}

impl Codec {
    pub fn new() -> Codec {
        Codec {}
    }
}

#[derive(Debug)]
pub struct OwnedPacket {
    pub header: pcap::PacketHeader,
    pub data: Vec<u8>,
}

impl From<Packet<'_>> for OwnedPacket {
    fn from(item: Packet<'_>) -> Self {
        Self {
            header: item.header.clone(),
            data: item.data.into(),
        }
    }
}

impl pcap::PacketCodec for Codec {
    type Item = OwnedPacket;

    fn decode(&mut self, packet: pcap::Packet) -> Self::Item {
        packet.into()
    }
}
