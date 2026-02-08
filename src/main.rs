mod audit;
mod model;
mod risk;

fn main() {
    let result = audit::npm().unwrap();
    println!(
        "Total Dependencies: {} \nTotal Vulnerabilities: {}",
        &result.metadata.dependencies.total, &result.metadata.vulnerabilities.total
    );
}
