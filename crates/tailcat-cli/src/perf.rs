//! Placeholder; replaced below.
use std::process::ExitCode;
pub const PORT: u16 = 5201;
#[derive(clap::Args, Debug)]
pub struct PerfArgs { addr: String }
pub async fn run(_g: &crate::Global, _a: PerfArgs) -> anyhow::Result<ExitCode> { anyhow::bail!("todo") }
pub struct Server;
impl Server {
    pub fn new() -> Self { Server }
    pub async fn handle_tcp(&self, _c: tailcat::TcpStream) {}
    pub async fn handle_udp(&self, _c: tailcat::UdpConn) {}
}
