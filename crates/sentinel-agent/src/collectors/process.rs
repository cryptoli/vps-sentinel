use crate::collectors::{CollectContext, Collector};
use crate::utils::procfs::{collect_processes, ProcfsRoot};
use async_trait::async_trait;
use sentinel_core::{RawEvent, SentinelResult};
use std::path::Path;

pub struct ProcessCollector;

#[async_trait]
impl Collector for ProcessCollector {
    fn name(&self) -> &'static str {
        "process"
    }

    async fn collect(&self, ctx: &CollectContext) -> SentinelResult<Vec<RawEvent>> {
        if !ctx.config.process.enabled {
            return Ok(Vec::new());
        }
        let proc_root = ctx.resolve(Path::new("/proc"));
        collect_processes(&ProcfsRoot::new(proc_root))
    }
}
