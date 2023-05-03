use anyhow::Context;
use clap::{Parser, Subcommand};

mod codec;
use codec::Codec;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: PcrustCommand,
}

#[derive(Subcommand)]
enum PcrustCommand {
    /// Pcap file to parse
    File {
        #[arg(required = true)]
        path: std::path::PathBuf,
    },
    /// Pcap directory to parse recursivly
    Dir {
        #[arg(required = true)]
        path: std::path::PathBuf,
    },

    /// Interface for live capture
    Interface {
        #[arg(required = true)]
        iface: std::path::PathBuf,
    },
}

fn scan_ntlm(payload: &[u8]) -> bool {
    use regex::bytes::Regex;
    let re = Regex::new(r"(?-u)NTLMSSP\x00\x02\x00\x00\x00").unwrap();

    re.is_match(payload)
}

fn parse_tcp_dump<T: pcap::Activated + ?Sized>(capture: pcap::Capture<T>) -> anyhow::Result<()> {
    let _results: Vec<anyhow::Result<()>> = capture
        .iter(Codec::new())
        .map(|packet| {
            let packet = packet?;
            let packet_header = etherparse::PacketHeaders::from_ip_slice(&packet.data[14..])
                .context("Couldn't parse ip packet.")?;

            println!("Has ntlmsspv2 hash? {}", scan_ntlm(packet_header.payload));

            Ok(())
        })
        .collect();

    Ok(())
}

fn scan_capture<T: pcap::Activated + ?Sized>(capture: pcap::Capture<T>) -> anyhow::Result<()> {
    let link_type = capture.get_datalink();
    match link_type {
        pcap::Linktype::ETHERNET => parse_tcp_dump(capture).context("Couldn't parse tcp dump")?,
        _ => anyhow::bail!(
            "We can't parse {}({}) yet.",
            link_type.get_name()?,
            link_type.get_description()?
        ),
    }

    Ok(())
}

fn parse_file(path: std::path::PathBuf) -> anyhow::Result<()> {
    let capture = pcap::Capture::from_file(&path)?;
    println!("version: {:?}", capture.version());

    scan_capture(capture)?;

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    match args.command {
        PcrustCommand::File { path } => parse_file(path).context("Couldn't parse file.")?,
        PcrustCommand::Dir { .. } => unimplemented!(),
        PcrustCommand::Interface { .. } => unimplemented!(),
    }

    Ok(())
}
