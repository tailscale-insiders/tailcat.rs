//! Bidirectional copying between connections.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::netstack::UdpConn;

/// Copies data between `a` and `b` in both directions until both sides
/// have finished. When one direction's source reaches EOF, the
/// destination gets a write shutdown, propagating TCP half-close rather
/// than tearing the connection down, so netcat-style protocols (send a
/// request, FIN, read the reply) work through the proxy.
///
/// It returns the byte counts copied a→b and b→a.
pub async fn proxy_conns<A, B>(a: A, b: B) -> (u64, u64)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut ar, mut aw) = tokio::io::split(a);
    let (mut br, mut bw) = tokio::io::split(b);
    tokio::join!(pipe(&mut ar, &mut bw), pipe(&mut br, &mut aw))
}

/// Copies `r` to `w` until EOF or an error on either side, then shuts
/// `w` down, returning the byte count copied.
pub(crate) async fn pipe<R, W>(r: &mut R, w: &mut W) -> u64
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; 64 << 10];
    let mut total = 0u64;
    while let Ok(n @ 1..) = r.read(&mut buf).await {
        if w.write_all(&buf[..n]).await.is_err() || w.flush().await.is_err() {
            break;
        }
        total += n as u64;
    }
    let _ = w.shutdown().await;
    total
}

/// Copies whole datagrams between a tunnel UDP flow and a connected OS
/// UDP socket until either side fails or `idle` passes with no traffic.
pub async fn proxy_packet_conns(a: &UdpConn, b: &tokio::net::UdpSocket, idle: Duration) {
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
        while let Ok(Ok(n)) = tokio::time::timeout(idle, b.recv(&mut buf)).await {
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
}
