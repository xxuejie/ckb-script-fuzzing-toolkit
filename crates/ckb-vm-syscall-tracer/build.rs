fn main() -> std::io::Result<()> {
    prost_build::compile_protos(&["protos/traces.proto"], &["protos/"])?;
    prost_reflect_build::Builder::new()
        .descriptor_pool("crate::generated::traces::DESCRIPTOR_POOL")
        .compile_protos(&["protos/traces.proto"], &["protos/"])?;
    Ok(())
}
