#[tokio::main]
async fn main() -> anyhow::Result<()> {
    proteus::cli::run().await
}
