use crate::model::NpmAudit;
use std::{path::Path, process::Command};

pub fn audit_npm() -> Result<NpmAudit, String> {
    let path = Path::new("/Users/santhoshc/learn/expense-tracker");

    let output = Command::new("npm")
        .arg("audit")
        .arg("--json")
        .current_dir(path)
        .output()
        .map_err(|e| format!("Failed to execute npm audit: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.trim().is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("npm audit produced no output: {}", stderr));
    }

    let json_output = serde_json::from_str(&stdout)
        .map_err(|e| format!("Failed to parse npm audit JSON: {}", e))?;

    Ok(json_output)
}
