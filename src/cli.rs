use core::fmt;

use crate::risk::Severity;
use clap::{Parser, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "deptriage")]
pub struct Args {
    #[arg(long)]
    pub only_direct: bool,

    #[arg(long, default_value_t = Severity::Low)]
    pub min_severity: Severity,

    #[arg(long)]
    pub only_fixable: bool,

    #[arg(long, short = 'i', default_value_t = InterfaceMode::Tui)]
    pub interface: InterfaceMode,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum InterfaceMode {
    Terminal,
    Tui,
}

impl fmt::Display for InterfaceMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            InterfaceMode::Terminal => "terminal",
            InterfaceMode::Tui => "tui",
        };

        write!(f, "{}", value)
    }
}
