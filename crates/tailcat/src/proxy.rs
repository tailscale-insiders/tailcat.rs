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
    let a_to_b = async {
        let n = copy(&mut ar, &mut bw).await;
        let _ = bw.shutdown().await;
        n
    };
    let b_to_a = async {
        let n = copy(&mut br, &mut aw).await;
        let _ = aw.shutdown().await;
        n
    };
    tokio::join!(a_to_b, b_to_a)
}

async fn copy<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(r: &mut R, w: &mut W) -> u64 {
    let mut buf = vec![0u8; 64 << 10];
    let mut total = 0u64;
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => return total,
            Ok(n) => n,
        };
        if w.write_all(&buf[..n]).await.is_err() {
            return total;
        }
        if w.flush().await.is_err() {
            return total;
        }
        total += n as u64;
    }
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
