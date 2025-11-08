mod client;
mod config;
mod runner;
mod stats;

use anyhow::Result;
use config::Config;
use runner::StressTest;

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration from environment and CLI args
    let config = Config::load()?;

    // Create and run the stress test
    let test = StressTest::new(config)?;
    test.run().await?;

    Ok(())
}
