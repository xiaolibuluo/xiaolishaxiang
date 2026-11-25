// Copyright (C) 小黎的部落（www.qingdujian.com）
// SPDX-License-Identifier: AGPL-3.0-only

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
