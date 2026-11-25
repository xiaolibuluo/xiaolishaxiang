fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure().compile_protos(
        &[
            "../../proto/xiaolishaxiang/v1/sandbox.proto",
            "../../proto/xiaolishaxiang/v1/scheduler.proto",
        ],
        &["../../proto"],
    )?;
    Ok(())
}
