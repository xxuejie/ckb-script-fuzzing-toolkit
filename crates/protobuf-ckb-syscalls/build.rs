fn main() -> std::io::Result<()> {
    let mut prost_build = prost_build::Config::new();
    prost_build.btree_map(["."]);
    prost_build.compile_protos(&["traces.proto"], &[""])?;
    prost_reflect_build::Builder::new()
        .descriptor_pool("crate::generated::traces::DESCRIPTOR_POOL")
        .compile_protos(&["traces.proto"], &[""])?;
    Ok(())
}
