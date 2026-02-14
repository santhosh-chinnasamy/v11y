use crate::risk::Severity;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "deptriage")]
pub struct Args {
    #[arg(long)]
    pub only_direct: bool,

    #[arg(long, default_value_t = Severity::Low)]
    pub min_severity: Severity,

    #[arg(long)]
    pub only_fixable: bool,
}
