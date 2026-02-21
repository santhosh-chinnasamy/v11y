use core::fmt;

use crate::risk::Severity;
use clap::{Parser, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "v11y", version, about, author, long_about = None)]
pub struct Args {
    #[arg(long)]
    pub only_direct: bool,

    #[arg(long, default_value_t = Severity::Low)]
    pub min_severity: Severity,

    #[arg(long)]
    pub only_fixable: bool,

    #[arg(long)]
    pub cli: bool,
}
