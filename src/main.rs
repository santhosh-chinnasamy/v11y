mod audit;
mod model;

fn main() {
    let result = audit::npm().unwrap();
    println!(
        "Total Dependencies: {} \nTotal Vulnerabilities: {}",
        &result.metadata.dependencies.total, &result.metadata.vulnerabilities.total
    );
}
