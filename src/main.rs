use anyhow::Context;
use clap::{Parser, Subcommand};

mod codec;
use codec::Codec;

mod scanner;

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

fn parse_tcp_dump<T: pcap::Activated + ?Sized>(capture: pcap::Capture<T>) -> anyhow::Result<()> {
    let mut state = scanner::ScanState::new();
    capture
        .iter(Codec::new())
        .map(|packet| {
            let packet = packet?;
            let packet_header = etherparse::PacketHeaders::from_ip_slice(&packet.data[14..])
                .context("Couldn't parse ip packet.")?;

            Ok(state
                .scan(packet_header.payload)
                .into_iter()
                .filter_map(|result| match result {
                    Ok(scanned) => Some(scanned),
                    Err(err) => {
                        tracing::warn!(warning = %err);
                        None
                    }
                })
                .filter_map(|scanned| scanned)
                .collect::<Vec<_>>())
        })
        .filter_map(|result: anyhow::Result<_>| match result {
            Ok(scanned) => Some(scanned),
            Err(err) => {
                tracing::warn!(warning = %err);
                None
            }
        })
        .filter(|scanned| scanned.len() != 0)
        .for_each(|scanned| println!("{scanned:#?}"));

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

    let log_subscriber = tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(tracing::Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(log_subscriber).context("Couldn't setup logging")?;

    match args.command {
        PcrustCommand::File { path } => parse_file(path).context("Couldn't parse file.")?,
        PcrustCommand::Dir { .. } => unimplemented!(),
        PcrustCommand::Interface { .. } => unimplemented!(),
    }

    Ok(())
}
