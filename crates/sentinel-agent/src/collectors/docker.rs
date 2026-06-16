use crate::collectors::{CollectContext, Collector};
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};
use std::path::Path;

pub struct DockerCollector;

#[async_trait]
impl Collector for DockerCollector {
    fn name(&self) -> &'static str {
        "docker"
    }

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        if !ctx.config.docker.enabled {
            return Ok(Vec::new());
        }

        let socket = ctx.resolve(Path::new("/var/run/docker.sock"));
        if socket.exists() {
            return Ok(vec![RawEvent::new("docker", "docker_socket")
                .with_field("path", socket.to_string_lossy().to_string())
                .with_field("exists", "true")]);
        }
        Ok(Vec::new())
    }
}
