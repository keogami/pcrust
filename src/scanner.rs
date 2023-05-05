#[derive(Debug)]
pub enum ScannedType {
    NTLMv1(String),
}

#[derive(Default)]
pub struct ScanState {
    partial_ntlm: Option<Vec<u8>>,
}

fn parse_ntlm(packet: &[u8], challenge: &[u8]) -> String {
    format!(
        "{}:{}",
        challenge
            .iter()
            .map(|i| format!("{i:02X}"))
            .fold("".to_owned(), |a, b| a + &b),
        packet
            .iter()
            .map(|i| format!("{i:02X}"))
            .fold("".to_owned(), |a, b| a + &b)
    )
}

fn scan_ntlm(state: &mut ScanState, payload: &[u8]) -> Option<ScannedType> {
    use regex::bytes::Regex;
    let ntlmssp2 = Regex::new(r"(?-u)NTLMSSP\x00\x02\x00\x00\x00.*[^EOF]*").unwrap();
    let ntlmssp3 = Regex::new(r"(?-u)NTLMSSP\x00\x03\x00\x00\x00.*[^EOF]*").unwrap();

    if state.partial_ntlm.is_none() {
        state.partial_ntlm = ntlmssp2
            .find(payload)
            .map(|m| Vec::from(&payload[m.start() + 24..m.start() + 32]));
        None
    } else {
        ntlmssp3.find(payload).map(|m| {
            ScannedType::NTLMv1(parse_ntlm(
                &payload[m.start()..m.end()],
                &state.partial_ntlm.take().unwrap(),
            ))
        })
    }
}

pub fn scan(state: &mut ScanState, payload: &[u8]) -> Vec<ScannedType> {
    [scan_ntlm]
        .iter()
        .filter_map(|f| f(state, payload))
        .collect()
}
