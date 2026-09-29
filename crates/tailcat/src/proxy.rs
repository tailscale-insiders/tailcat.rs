//! Bidirectional copying between connections.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::netstack::UdpConn;

/// Copies data between `a` and `b` in both directions until both sides
/// have finished. When one direction's source reaches EOF, the
/// destination gets a write shutdown, propagating TCP half-close rather
/// than tearing the connection down, so netcat-style protocols (send a
/// request, FIN, read the reply) work through the proxy. An error in
/// either direction (a reset) ends both: the other side's peer may
/// never close its end otherwise.
///
/// It returns the byte counts copied a→b and b→a.
pub async fn proxy_conns<A, B>(a: A, b: B) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    let (mut ab, mut ba) = (0, 0);
    let _ = tokio::try_join!(copy(&mut ar, &mut bw, &mut ab), copy(&mut br, &mut aw, &mut ba));
    (ab, ba)
}

/// Copies `r` to `w` until EOF or an error on either side, then shuts
/// `w` down, returning the byte count copied.
pub(crate) async fn pipe<R, W>(r: &mut R, w: &mut W) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut total = 0;
    let _ = copy(r, w, &mut total).await;
    total
}

/// Copies `r` to `w`, counting bytes into `total`, until EOF or an error
/// on either side, then shuts `w` down; it reports the error, if any.
async fn copy<R, W>(r: &mut R, w: &mut W, total: &mut u64) -> std::io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 64 << 10];
    let r = async {
        loop {
            let n = r.read(&mut buf).await?;
            if n == 0 {
                return Ok(());
            }
            w.write_all(&buf[..n]).await?;
            w.flush().await?;
            *total += n as u64;
        }
    }
    .await;
    let _ = w.shutdown().await;
    r
}

/// Copies whole datagrams between a tunnel UDP flow and a connected OS
/// UDP socket until either side fails or `idle` passes with no traffic
/// either way. It sets `a`'s idle timeout, which counts both.
pub async fn proxy_packet_conns(a: &UdpConn, b: &tokio::net::UdpSocket, idle: Duration) {
    a.set_idle_timeout(Some(idle));
    let a_to_b = async {
        let mut buf = vec![0u8; 65535];
        while let Ok(n) = a.recv(&mut buf).await {
            if b.send(&buf[..n]).await.is_err() {
                break;
            }
        }
    };
    let b_to_a = async {
        let mut buf = vec![0u8; 65535];
        while let Ok(n) = b.recv(&mut buf).await {
            if a.send(&buf[..n]).await.is_err() {
                break;
            }
        }
    };
    tokio::select! {
        _ = a_to_b => {}
        _ = b_to_a => {}
    }
    a.close();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each direction half-closes on its own: `a` finishes sending and
    /// still gets `b`'s reply.
    #[tokio::test]
    async fn proxy_conns_propagates_half_close() {
        let (mut a, a_far) = tokio::io::duplex(1024);
        let (mut b, b_far) = tokio::io::duplex(1024);
        let proxy = tokio::spawn(proxy_conns(a_far, b_far));

        a.write_all(b"request").await.unwrap();
        a.shutdown().await.unwrap();
        let mut req = Vec::new();
        b.read_to_end(&mut req).await.unwrap();
        assert_eq!(req, b"request");

        b.write_all(b"a longer reply").await.unwrap();
        b.shutdown().await.unwrap();
        let mut reply = Vec::new();
        a.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"a longer reply");

        assert_eq!(proxy.await.unwrap(), (7, 14));
    }

    /// A connection whose reads fail, as a reset one's do.
    struct Reset;

    impl AsyncRead for Reset {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
        }
    }

    impl AsyncWrite for Reset {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::ErrorKind::ConnectionReset.into()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    /// When one side resets, the proxy ends, and closes the other side,
    /// even if that side's peer ignores the FIN and stays quiet.
    #[tokio::test]
    async fn proxy_conns_ends_when_a_side_resets() {
        let (mut b, b_far) = tokio::io::duplex(1024);
        let proxy = tokio::spawn(proxy_conns(Reset, b_far));
        let counts = tokio::time::timeout(Duration::from_secs(5), proxy).await.expect("proxy still running");
        assert_eq!(counts.unwrap(), (0, 0));
        // `b` sees its connection closed, not just half-closed: writes fail.
        assert_eq!(b.read(&mut [0; 1]).await.unwrap(), 0);
        assert!(b.write_all(b"x").await.is_err());
    }

    /// Traffic into the tunnel flow alone keeps it open, as for a service
    /// that never answers (syslog, say), and a quiet flow still ends.
    #[tokio::test]
    async fn one_way_packet_flows_stay_open() {
        use std::net::{IpAddr, SocketAddr};
        use std::sync::Arc;

        use crate::netstack::{Stack, StackConfig, build_udp};

        let (me, far): (IpAddr, SocketAddr) = ("fd7a::1".parse().unwrap(), "[fd7a::2]:514".parse().unwrap());
        let stack = Stack::new(StackConfig { addrs: vec![me], any_ip: false, mtu: 1280 }, Arc::new(|_| {}), None, None);
        let a = stack.dial_udp(me, far).unwrap();
        let local = a.local_addr();
        let service = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        b.connect(service.local_addr().unwrap()).await.unwrap();
        let idle = Duration::from_millis(300);
        let proxy = tokio::spawn(async move { proxy_packet_conns(&a, &b, idle).await });
        let mut buf = [0u8; 16];
        for i in 0..8u8 {
            stack.inject(build_udp(far, local, &[i]).unwrap());
            let got = tokio::time::timeout(Duration::from_secs(1), service.recv(&mut buf)).await;
            assert_eq!(got.expect("the flow ended").unwrap(), 1);
            assert_eq!(buf[0], i);
            tokio::time::sleep(idle / 3).await;
        }
        assert!(!proxy.is_finished());
        tokio::time::timeout(idle * 3, proxy).await.expect("the idle flow stayed open").unwrap();
    }
}
