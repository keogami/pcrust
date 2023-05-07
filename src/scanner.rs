use anyhow::Context;
use byteorder::{LittleEndian, ReadBytesExt};
use std::{fmt::Display, ops::Range};

#[derive(Debug)]
pub enum NTLMType {
    V1,
    V2,
    Unknown,
}

#[derive(Debug)]
pub struct NTLM {
    pub nt_hash: Vec<u8>,
    pub lm_hash: Vec<u8>,
    pub domain: String,
    pub user: String,
    pub challenge: Vec<u8>,
}

impl NTLM {
    fn version(&self) -> NTLMType {
        match self.nt_hash.len() {
            24 => NTLMType::V1,
            n if n > 60 => NTLMType::V2,
            _ => NTLMType::Unknown,
        }
    }
}

impl Display for NTLM {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.version() {
            NTLMType::V1 => write!(
                f,
                "NTLMv1 {}::{}:{}:{}:{}",
                self.user,
                self.domain,
                hex::encode(&self.lm_hash),
                hex::encode(&self.nt_hash),
                hex::encode(&self.challenge),
            ),
            NTLMType::V2 => write!(
                f,
                "NTLMv2 {}::{}:{}:{}:{}",
                self.user,
                self.domain,
                hex::encode(&self.challenge),
                hex::encode(&self.nt_hash[..16]),
                hex::encode(&self.nt_hash[16..])
            ),
            NTLMType::Unknown => write!(f, "Malformed NTLM"),
        }
    }
}

#[inline]
fn extract_from_buffer(
    buffer: &[u8],
    len_range: Range<usize>,
    offset_range: Range<usize>,
) -> anyhow::Result<&[u8]> {
    let len = (&buffer[len_range]).read_u16::<LittleEndian>()? as usize;
    let offset = (&buffer[offset_range]).read_u16::<LittleEndian>()? as usize;

    tracing::debug!(%len, %offset, buffer_len = %buffer.len(), underflow = %(len + offset > buffer.len()));

    if offset + len > buffer.len() {
        if len > 1 {
            hexdump::hexdump(buffer);
        }
        anyhow::bail!("Not enough data in buffer")
    }

    Ok(&buffer[offset..offset + len])
}

impl TryFrom<(&[u8], &[u8])> for NTLM {
    type Error = anyhow::Error;

    #[inline]
    fn try_from((value, challenge): (&[u8], &[u8])) -> anyhow::Result<NTLM> {
        let challenge = Vec::from(challenge);

        let nt_hash = extract_from_buffer(value, 22..24, 24..26)?;
        let nt_hash = Vec::from(nt_hash);

        let lm_hash = if nt_hash.len() == 24 {
            Vec::from(extract_from_buffer(value, 14..16, 16..18)?)
        } else {
            Vec::new()
        };

        let domain: String = extract_from_buffer(value, 30..32, 32..34)?
            .into_iter()
            .filter(|&&c| c != 0)
            .map(|&c| c as char)
            .collect();

        let user: String = extract_from_buffer(value, 38..40, 40..42)?
            .into_iter()
            .filter(|&&c| c != 0)
            .map(|&c| c as char)
            .collect();

        Ok(NTLM {
            nt_hash,
            lm_hash,
            domain,
            user,
            challenge,
        })
    }
}

#[derive(Debug)]
pub enum ScannedType {
    NTLM(NTLM),
}

impl Display for ScannedType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScannedType::NTLM(ntlm) => write!(f, "{ntlm}"),
        }
    }
}

#[derive(Default)]
pub struct ScanState {
    partial_ntlm: Option<Vec<u8>>,
}

impl ScanState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn scan(&mut self, payload: &[u8]) -> Vec<anyhow::Result<Option<ScannedType>>> {
        [scan_ntlm].iter().map(|f| f(self, payload)).collect()
    }
}

fn parse_ntlm(data: &[u8], challenge: &[u8]) -> anyhow::Result<ScannedType> {
    let ntlm: NTLM = (data, challenge)
        .try_into()
        .context("Couldn't parse ntlm hash")?;

    Ok(ScannedType::NTLM(ntlm))
}

fn scan_ntlm(state: &mut ScanState, payload: &[u8]) -> anyhow::Result<Option<ScannedType>> {
    use regex::bytes::Regex;
    let ntlmssp2 = Regex::new(r"(?-u)NTLMSSP\x00\x02\x00\x00\x00.*[^EOF]*").unwrap();
    let ntlmssp3 = Regex::new(r"(?-u)NTLMSSP\x00\x03\x00\x00\x00.*[^EOF]*").unwrap();

    if state.partial_ntlm.is_none() {
        state.partial_ntlm = ntlmssp2
            .find(payload)
            .map(|m| Vec::from(&payload[m.start() + 24..m.start() + 32]));
        Ok(None)
    } else {
        Ok(match ntlmssp3.find(payload) {
            Some(m)
                if (&payload[m.start() + 22..m.start() + 24]).read_u16::<LittleEndian>()? <= 1 =>
            {
                None
            }
            Some(m) => {
                // It seems sometimes the regex returns a range such that m.end() < payload.len()
                // and when we use &payload[m.start()..m.end()] for further processing, the buffer ends up being too short.
                // But using the the entire payload starting from m.start() seems to give the same output as PCredz.

                // Looking at the regex that we have shamelessly copied from the PCredz, the `^[EOF]*` part looks fishy.
                // Looking at the NTLM spec, the ntlm_payload size depends on the structures that precede the ntlm_payload,
                // which implies that it shouldn't be possible to discern the size of ntlm_payload without parsing.

                // Passing the entire payload should be safe.
                let res = parse_ntlm(&payload[m.start()..], &state.partial_ntlm.as_ref().unwrap())?;
                state.partial_ntlm = None;

                Some(res)
            }
            None => None,
        })
    }
}
