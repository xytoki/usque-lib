use anyhow::{bail, Result};
use bytes::Bytes;
use futures::{Future, Sink, Stream};
use octets::Octets;
use quiche::h3::NameValue;
use ring::rand::SecureRandom;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::time::{Instant, Sleep};

use crate::config::Config;
use crate::icmp;
use crate::mtu::max_datagram_size;
use crate::packet;
use crate::tls;
use crate::udp_socket::bind_udp_socket;

const DEFAULT_QUEUE_CAPACITY: usize = 4096;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct PacketSessionConfig {
    pub endpoint: SocketAddr,
    pub bind: Option<SocketAddr>,
    pub sni: String,
    pub keepalive_period: Duration,
    pub mtu: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketSessionState {
    Idle,
    Connecting,
    Handshaking,
    Ready,
    Reconnecting,
    Closed,
}

#[derive(Debug, Clone)]
enum SessionLoopOutcome {
    Reconnect(String),
}

impl SessionLoopOutcome {
    fn into_message(self) -> String {
        match self {
            Self::Reconnect(reason) => reason,
        }
    }
}

pub struct MasquePacketStream {
    socket: tokio::net::UdpSocket,
    conn: quiche::Connection,
    h3_conn: quiche::h3::Connection,
    connect_stream_id: u64,
    flow_id: u64,
    flow_prefix: Vec<u8>,
    mtu: u16,
    outbound_queue: VecDeque<Bytes>,
    inbound_queue: VecDeque<Bytes>,
    out: Vec<u8>,
    buf: Vec<u8>,
    local_addr: SocketAddr,
    endpoint: SocketAddr,
    state: PacketSessionState,
    timeout: Pin<Box<Sleep>>,
    has_timeout: bool,
    pending_send: Option<PendingUdpSend>,
    terminal_error: Option<String>,
    emitted_terminal_error: bool,
}

struct PendingUdpSend {
    len: usize,
    to: SocketAddr,
}

impl MasquePacketStream {
    pub async fn connect(config: Arc<Config>, session_cfg: PacketSessionConfig) -> Result<Self> {
        let tls_material = tls::prepare_tls_material(config.as_ref())?;
        let mut quic_config = build_quic_config(&tls_material, session_cfg.mtu)?;

        let bind_addr: SocketAddr =
            session_cfg
                .bind
                .unwrap_or_else(|| match session_cfg.endpoint {
                    SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
                    SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
                });

        let socket = bind_udp_socket(bind_addr, "masque-packet-stream")?;
        socket.connect(session_cfg.endpoint).await?;
        let local_addr = socket.local_addr()?;

        let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
        ring::rand::SystemRandom::new()
            .fill(&mut scid)
            .map_err(|_| anyhow::anyhow!("RNG failure"))?;
        let scid = quiche::ConnectionId::from_ref(&scid);

        let mut conn = quiche::connect(
            Some(&session_cfg.sni),
            &scid,
            local_addr,
            session_cfg.endpoint,
            &mut quic_config,
        )?;

        let mut out = vec![0u8; max_datagram_size(session_cfg.mtu)];
        let mut buf = vec![0u8; 65535];

        let (h3_conn, stream_id, flow_id) = tokio::time::timeout(CONNECT_TIMEOUT, async {
            flush_conn_send(&socket, &mut conn, &mut out).await?;

            if let Some(outcome) = complete_handshake(
                &socket,
                &mut conn,
                &mut out,
                &mut buf,
                local_addr,
                session_cfg.endpoint,
            )
            .await
            {
                return Err(anyhow::anyhow!(outcome.into_message()));
            }

            if let Some(peer_cert) = conn.peer_cert() {
                if !tls::verify_endpoint_key(peer_cert, &tls_material.endpoint_pub_key_spki_der) {
                    bail!("peer certificate public key does not match pinned endpoint key");
                }
            }

            let mut h3_config = quiche::h3::Config::new()?;
            h3_config.enable_extended_connect(true);

            let mut h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)?;

            let req = vec![
                quiche::h3::Header::new(b":method", b"CONNECT"),
                quiche::h3::Header::new(b":protocol", b"cf-connect-ip"),
                quiche::h3::Header::new(b":scheme", b"https"),
                quiche::h3::Header::new(b":authority", b"cloudflareaccess.com"),
                quiche::h3::Header::new(b":path", b"/"),
                quiche::h3::Header::new(b"capsule-protocol", b"?1"),
                quiche::h3::Header::new(b"user-agent", b""),
            ];

            let stream_id = h3_conn.send_request(&mut conn, &req, false)?;
            let flow_id = stream_id / 4;

            flush_conn_send(&socket, &mut conn, &mut out).await?;

            if let Some(outcome) = wait_for_connect_response(
                &socket,
                &mut conn,
                &mut h3_conn,
                &mut out,
                &mut buf,
                local_addr,
                session_cfg.endpoint,
                stream_id,
            )
            .await
            {
                return Err(anyhow::anyhow!(outcome.into_message()));
            }

            Ok::<_, anyhow::Error>((h3_conn, stream_id, flow_id))
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!("MASQUE connect timed out after {}s", CONNECT_TIMEOUT.as_secs())
        })??;

        let mut stream = Self {
            socket,
            conn,
            h3_conn,
            connect_stream_id: stream_id,
            flow_id,
            flow_prefix: build_flow_prefix(flow_id),
            mtu: session_cfg.mtu.min(u32::from(u16::MAX)) as u16,
            outbound_queue: VecDeque::new(),
            inbound_queue: VecDeque::new(),
            out,
            buf,
            local_addr,
            endpoint: session_cfg.endpoint,
            state: PacketSessionState::Ready,
            timeout: Box::pin(tokio::time::sleep(Duration::from_millis(0))),
            has_timeout: false,
            pending_send: None,
            terminal_error: None,
            emitted_terminal_error: false,
        };
        stream.reset_timeout();
        Ok(stream)
    }

    pub fn state(&self) -> PacketSessionState {
        self.state
    }

    pub async fn close(&mut self) -> io::Result<()> {
        futures::future::poll_fn(|cx| Pin::new(&mut *self).poll_close(cx)).await
    }

    fn reset_timeout(&mut self) {
        match self.conn.timeout() {
            Some(duration) => {
                self.timeout.as_mut().reset(Instant::now() + duration);
                self.has_timeout = true;
            }
            None => {
                self.has_timeout = false;
            }
        }
    }

    fn set_terminal_error(&mut self, error: impl Into<String>) {
        self.state = PacketSessionState::Closed;
        if self.terminal_error.is_none() {
            self.terminal_error = Some(error.into());
        }
    }

    fn terminal_io_error(&self) -> io::Error {
        io::Error::other(
            self.terminal_error
                .clone()
                .unwrap_or_else(|| "MASQUE stream closed".to_string()),
        )
    }

    fn closed_io_error(&self) -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "MASQUE stream closed")
    }

    fn poll_drive(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut progressed = false;

        loop {
            let mut made_progress = false;

            made_progress |= flush_pending_queue(
                &mut self.conn,
                &self.flow_prefix,
                self.mtu,
                &mut self.outbound_queue,
                &mut self.inbound_queue,
            );
            match self.poll_flush_conn_send(cx) {
                Poll::Ready(Ok(flushed)) => made_progress |= flushed,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }

            match self.poll_recv_udp(cx) {
                Poll::Ready(Ok(received)) => made_progress |= received,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }

            made_progress |= self.poll_h3_events()?;
            made_progress |= self.poll_incoming_datagrams()?;

            let timeout_due = self.conn.timeout().is_some_and(|d| d.is_zero())
                || (self.has_timeout && self.timeout.as_mut().poll(cx).is_ready());
            if timeout_due {
                self.conn.on_timeout();
                self.reset_timeout();
                made_progress = true;
            }

            match self.poll_flush_conn_send(cx) {
                Poll::Ready(Ok(flushed)) => made_progress |= flushed,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }

            if self.conn.is_closed() {
                return Poll::Ready(Err(io::Error::other("MASQUE connection closed")));
            }

            if !made_progress {
                return if progressed {
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Pending
                };
            }

            progressed = true;
        }
    }

    fn poll_recv_udp(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let mut received = false;

        loop {
            match self.socket.poll_recv_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {
                    return if received {
                        Poll::Ready(Ok(true))
                    } else {
                        Poll::Pending
                    };
                }
            }

            loop {
                match self.socket.try_recv(&mut self.buf) {
                    Ok(len) => {
                        let recv_info = quiche::RecvInfo {
                            to: self.local_addr,
                            from: self.endpoint,
                        };
                        if let Err(error) = self.conn.recv(&mut self.buf[..len], recv_info) {
                            log::debug!("quic recv error: {error}");
                        }
                        received = true;
                        self.reset_timeout();
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
        }
    }

    fn poll_flush_conn_send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let mut flushed = false;

        loop {
            if self.pending_send.is_none() {
                let (write, send_info) = match self.conn.send(&mut self.out) {
                    Ok(result) => result,
                    Err(quiche::Error::Done) => return Poll::Ready(Ok(flushed)),
                    Err(error) => return Poll::Ready(Err(io::Error::other(error.to_string()))),
                };

                self.pending_send = Some(PendingUdpSend {
                    len: write,
                    to: send_info.to,
                });
                self.reset_timeout();
            }

            match self.socket.poll_send_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {
                    return if flushed {
                        Poll::Ready(Ok(true))
                    } else {
                        Poll::Pending
                    };
                }
            }

            let pending = self.pending_send.as_ref().unwrap();
            if pending.to != self.endpoint {
                return Poll::Ready(Err(io::Error::other(format!(
                    "unexpected QUIC send target {} (expected {})",
                    pending.to, self.endpoint
                ))));
            }

            match self.socket.try_send(&self.out[..pending.len]) {
                Ok(sent) if sent == pending.len => {
                    self.pending_send = None;
                    flushed = true;
                }
                Ok(_) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "partial UDP send",
                    )));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    // try_send 返回 WouldBlock 后回到循环顶部，由 poll_send_ready 注册写唤醒。
                    continue;
                }
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
    }

    fn poll_h3_events(&mut self) -> io::Result<bool> {
        let mut progressed = false;

        loop {
            match self.h3_conn.poll(&mut self.conn) {
                Ok((stream_id, event)) => {
                    progressed = true;
                    self.handle_h3_event(stream_id, &event)?;
                }
                Err(quiche::h3::Error::Done) => return Ok(progressed),
                Err(error) => return Err(io::Error::other(format!("h3 poll error: {error}"))),
            }
        }
    }

    /// CONNECT 流的事件处置。流被对端关闭或 reset 就是隧道终结：
    /// 数据报是连接级的，流死了发送照样成功、包却全部石沉大海，
    /// 所以必须盯住事件。Data 事件把 capsule 读掉，免得占着流的
    /// 接收窗口。
    fn handle_h3_event(&mut self, stream_id: u64, event: &quiche::h3::Event) -> io::Result<()> {
        if stream_id != self.connect_stream_id {
            return Ok(());
        }
        match event {
            quiche::h3::Event::Finished => Err(io::Error::other("MASQUE CONNECT flow closed")),
            quiche::h3::Event::Reset(code) => Err(io::Error::other(format!(
                "MASQUE CONNECT flow reset (code {code})"
            ))),
            quiche::h3::Event::Data => loop {
                match self
                    .h3_conn
                    .recv_body(&mut self.conn, stream_id, &mut self.buf)
                {
                    Ok(_) => {}
                    Err(quiche::h3::Error::Done) => return Ok(()),
                    Err(error) => {
                        return Err(io::Error::other(format!("h3 recv_body error: {error}")))
                    }
                }
            },
            _ => Ok(()),
        }
    }

    fn poll_incoming_datagrams(&mut self) -> io::Result<bool> {
        let mut progressed = false;

        loop {
            if self.inbound_queue.len() >= DEFAULT_QUEUE_CAPACITY {
                return Ok(progressed);
            }

            match self.conn.dgram_recv_buf() {
                Ok(dgram) => {
                    progressed = true;
                    if let Some(offset) = parse_datagram_offset(&dgram, self.flow_id) {
                        let dgram = Bytes::from(dgram);
                        let packet = dgram.slice(offset..);
                        if packet::validate_incoming(packet.as_ref()).is_ok() {
                            self.inbound_queue.push_back(packet);
                        }
                    }
                }
                Err(quiche::Error::Done) => return Ok(progressed),
                Err(error) => {
                    log::debug!("dgram recv error: {error}");
                    return Ok(progressed);
                }
            }
        }
    }
}

impl Stream for MasquePacketStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if let Some(packet) = self.inbound_queue.pop_front() {
                return Poll::Ready(Some(Ok(packet)));
            }

            if self.emitted_terminal_error {
                return Poll::Ready(None);
            }

            if self.terminal_error.is_some() {
                self.emitted_terminal_error = true;
                return Poll::Ready(Some(Err(self.terminal_io_error())));
            }

            match self.poll_drive(cx) {
                Poll::Ready(Ok(())) => continue,
                Poll::Ready(Err(error)) => {
                    self.set_terminal_error(error.to_string());
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Sink<Bytes> for MasquePacketStream {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.state == PacketSessionState::Closed {
            return Poll::Ready(Err(self.closed_io_error()));
        }

        if self.terminal_error.is_some() {
            return Poll::Ready(Err(self.terminal_io_error()));
        }

        if self.outbound_queue.len() >= DEFAULT_QUEUE_CAPACITY {
            match self.poll_drive(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => {
                    self.set_terminal_error(error.to_string());
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.outbound_queue.len() < DEFAULT_QUEUE_CAPACITY {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> io::Result<()> {
        if self.state == PacketSessionState::Closed {
            return Err(self.closed_io_error());
        }

        if self.terminal_error.is_some() {
            return Err(self.terminal_io_error());
        }

        if self.outbound_queue.len() >= DEFAULT_QUEUE_CAPACITY {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "MASQUE outbound queue is full",
            ));
        }

        self.outbound_queue.push_back(item);
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.terminal_error.is_some() {
                return Poll::Ready(Err(self.terminal_io_error()));
            }

            let queue_before = self.outbound_queue.len();
            match self.poll_drive(cx) {
                Poll::Ready(Ok(())) => {
                    if self.outbound_queue.is_empty() && self.pending_send.is_none() {
                        return Poll::Ready(Ok(()));
                    }

                    if self.outbound_queue.len() == queue_before {
                        return Poll::Pending;
                    }
                }
                Poll::Ready(Err(error)) => {
                    self.set_terminal_error(error.to_string());
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => {
                    if self.outbound_queue.is_empty() && self.pending_send.is_none() {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Pending;
                }
            }
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.terminal_error.is_none() {
            self.conn.close(true, 0, b"stream closed").ok();
        }

        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {
                self.state = PacketSessionState::Closed;
                self.emitted_terminal_error = true;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => {
                self.set_terminal_error(error.to_string());
                Poll::Ready(Err(error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

fn build_quic_config(tls_material: &tls::TlsMaterial, mtu: u32) -> Result<quiche::Config> {
    let mut quic_config = quiche::Config::new(quiche::PROTOCOL_VERSION)
        .map_err(|e| anyhow::anyhow!("quiche config: {e}"))?;

    quic_config.verify_peer(false);
    quic_config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|e| anyhow::anyhow!("set ALPN: {e}"))?;
    quic_config
        .load_cert_chain_from_pem_file(tls_material.cert_pem_file.path().to_str().unwrap())
        .map_err(|e| anyhow::anyhow!("load cert: {e}"))?;
    quic_config
        .load_priv_key_from_pem_file(tls_material.key_pem_file.path().to_str().unwrap())
        .map_err(|e| anyhow::anyhow!("load key: {e}"))?;

    // 空闲 60 秒即关闭，与 quic-go 的默认一致。两边都设 0 的话这个
    // 超时会被完全禁用，连接死了也察觉不到。正常流量会不断重置
    // 计时器；空闲的链路到点断开，等下次有包再重连。
    quic_config.set_max_idle_timeout(60_000);
    quic_config.set_max_recv_udp_payload_size(max_datagram_size(mtu));
    quic_config.set_max_send_udp_payload_size(max_datagram_size(mtu));
    quic_config.set_initial_max_data(10_000_000);
    quic_config.set_initial_max_stream_data_bidi_local(1_000_000);
    quic_config.set_initial_max_stream_data_bidi_remote(1_000_000);
    quic_config.set_initial_max_stream_data_uni(1_000_000);
    quic_config.set_initial_max_streams_bidi(100);
    quic_config.set_initial_max_streams_uni(100);
    quic_config.set_disable_active_migration(true);
    quic_config.enable_dgram(true, 1000, 1000);

    Ok(quic_config)
}

async fn complete_handshake(
    socket: &tokio::net::UdpSocket,
    conn: &mut quiche::Connection,
    out: &mut [u8],
    buf: &mut [u8],
    local_addr: SocketAddr,
    endpoint: SocketAddr,
) -> Option<SessionLoopOutcome> {
    loop {
        let timeout = conn.timeout().unwrap_or(Duration::from_millis(100));

        tokio::select! {
            result = socket.recv(buf) => {
                match result {
                    Ok(len) => {
                        let recv_info = quiche::RecvInfo { to: local_addr, from: endpoint };
                        conn.recv(&mut buf[..len], recv_info).ok();
                    }
                    Err(error) => return Some(SessionLoopOutcome::Reconnect(format!("UDP recv during handshake failed: {error}"))),
                }
            }
            () = tokio::time::sleep(timeout) => {
                conn.on_timeout();
            }
        }

        if let Err(error) = flush_conn_send(socket, conn, out).await {
            return Some(SessionLoopOutcome::Reconnect(format!(
                "send during handshake failed: {error}"
            )));
        }

        if conn.is_established() {
            return None;
        }
        if conn.is_closed() {
            return Some(SessionLoopOutcome::Reconnect(
                "connection closed during handshake".to_string(),
            ));
        }
    }
}

async fn wait_for_connect_response(
    socket: &tokio::net::UdpSocket,
    conn: &mut quiche::Connection,
    h3_conn: &mut quiche::h3::Connection,
    out: &mut [u8],
    buf: &mut [u8],
    local_addr: SocketAddr,
    endpoint: SocketAddr,
    stream_id: u64,
) -> Option<SessionLoopOutcome> {
    let mut connect_established = false;

    for _ in 0..100 {
        let timeout = conn.timeout().unwrap_or(Duration::from_millis(100));

        tokio::select! {
            result = socket.recv(buf) => {
                match result {
                    Ok(len) => {
                        let recv_info = quiche::RecvInfo { to: local_addr, from: endpoint };
                        conn.recv(&mut buf[..len], recv_info).ok();
                    }
                    Err(error) => return Some(SessionLoopOutcome::Reconnect(format!("UDP recv before CONNECT response failed: {error}"))),
                }
            }
            () = tokio::time::sleep(timeout) => {
                conn.on_timeout();
            }
        }

        loop {
            match h3_conn.poll(conn) {
                Ok((sid, quiche::h3::Event::Headers { list, more_frames: _ })) if sid == stream_id => {
                    for header in &list {
                        if header.name() == b":status" {
                            let status = std::str::from_utf8(header.value()).unwrap_or("?");
                            if status.starts_with('2') {
                                connect_established = true;
                            } else {
                                return Some(SessionLoopOutcome::Reconnect(format!(
                                    "CONNECT rejected with status {status}"
                                )));
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(quiche::h3::Error::Done) => break,
                Err(error) => {
                    return Some(SessionLoopOutcome::Reconnect(format!(
                        "h3 poll error: {error}"
                    )));
                }
            }
        }

        if let Err(error) = flush_conn_send(socket, conn, out).await {
            return Some(SessionLoopOutcome::Reconnect(format!(
                "send during CONNECT wait failed: {error}"
            )));
        }

        if connect_established {
            return None;
        }
        if conn.is_closed() {
            return Some(SessionLoopOutcome::Reconnect(
                "connection closed before CONNECT response".to_string(),
            ));
        }
    }

    Some(SessionLoopOutcome::Reconnect(
        "timed out waiting for CONNECT response".to_string(),
    ))
}

async fn flush_conn_send(
    socket: &tokio::net::UdpSocket,
    conn: &mut quiche::Connection,
    out: &mut [u8],
) -> Result<()> {
    loop {
        match conn.send(out) {
            Ok((write, send_info)) => {
                socket.send_to(&out[..write], send_info.to).await?;
            }
            Err(quiche::Error::Done) => break,
            Err(error) => bail!("{error}"),
        }
    }
    Ok(())
}

fn flush_pending_queue(
    conn: &mut quiche::Connection,
    flow_prefix: &[u8],
    mtu: u16,
    queue: &mut VecDeque<Bytes>,
    inbound_queue: &mut VecDeque<Bytes>,
) -> bool {
    let mut progressed = false;

    while let Some(packet) = queue.front() {
        if conn.is_dgram_send_queue_full() {
            break;
        }

        match build_flow_datagram(flow_prefix, packet) {
            Some(dgram) => match conn.dgram_send_buf(dgram) {
                Ok(()) | Err(quiche::Error::InvalidState) => {
                    let _ = queue.pop_front();
                    progressed = true;
                }
                Err(quiche::Error::Done) => {
                    break;
                }
                Err(error) => {
                    let Some(packet) = queue.pop_front() else {
                        break;
                    };
                    progressed = true;
                    let effective_mtu = effective_inner_mtu(
                        conn.dgram_max_writable_len(),
                        flow_prefix.len(),
                        mtu,
                    );
                    log::debug!(
                        "datagram send error: {error}, generating ICMP Packet Too Big (mtu={effective_mtu})"
                    );
                    if inbound_queue.len() < DEFAULT_QUEUE_CAPACITY {
                        if let Some(icmp_pkt) = icmp::compose_icmp_too_large(&packet, effective_mtu)
                        {
                            inbound_queue.push_back(Bytes::from(icmp_pkt));
                        }
                    }
                }
            },
            None => {
                let _ = queue.pop_front();
                progressed = true;
                log::trace!("dropping outgoing packet before MASQUE send");
            }
        }
    }

    progressed
}

fn effective_inner_mtu(
    dgram_max_writable: Option<usize>,
    flow_prefix_len: usize,
    configured_mtu: u16,
) -> u16 {
    dgram_max_writable
        .and_then(|max_len| max_len.checked_sub(flow_prefix_len))
        .and_then(|inner_mtu| u16::try_from(inner_mtu).ok())
        .filter(|&inner_mtu| inner_mtu > 0)
        .map_or(configured_mtu, |inner_mtu| inner_mtu.min(configured_mtu))
}

fn build_flow_datagram(flow_prefix: &[u8], packet: &[u8]) -> Option<Vec<u8>> {
    let mut dgram = Vec::with_capacity(flow_prefix.len() + packet.len());
    dgram.extend_from_slice(flow_prefix);
    dgram.extend_from_slice(packet);
    if packet::prepare_outgoing(&mut dgram[flow_prefix.len()..]).is_ok() {
        Some(dgram)
    } else {
        None
    }
}

fn build_flow_prefix(flow_id: u64) -> Vec<u8> {
    let mut prefix = Vec::with_capacity(16);
    let mut tmp = [0u8; 8];
    let mut builder = octets::OctetsMut::with_slice(&mut tmp);
    builder.put_varint(flow_id).unwrap();
    let len = builder.off();
    drop(builder);
    prefix.extend_from_slice(&tmp[..len]);
    prefix.push(0x00);
    prefix
}

fn parse_datagram_offset(dgram: &[u8], expected_flow_id: u64) -> Option<usize> {
    let mut bytes = Octets::with_slice(dgram);
    let flow_id = bytes.get_varint().ok()?;
    if flow_id != expected_flow_id {
        return None;
    }
    let context_id = bytes.get_varint().ok()?;
    if context_id != 0 {
        return None;
    }
    let offset = bytes.off();
    if offset >= dgram.len() {
        return None;
    }
    Some(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_varint(value: u64) -> Vec<u8> {
        let mut tmp = [0u8; 8];
        let mut builder = octets::OctetsMut::with_slice(&mut tmp);
        builder.put_varint(value).unwrap();
        let len = builder.off();
        drop(builder);
        tmp[..len].to_vec()
    }

    #[test]
    fn parse_datagram_offset_valid() {
        let payload = b"hello";
        let mut datagram = Vec::new();
        datagram.extend_from_slice(&encode_varint(0));
        datagram.extend_from_slice(&encode_varint(0));
        datagram.extend_from_slice(payload);

        let offset = parse_datagram_offset(&datagram, 0).unwrap();
        assert_eq!(&datagram[offset..], payload);
    }

    #[test]
    fn build_flow_datagram_prepares_ttl() {
        let flow_prefix = build_flow_prefix(0);
        let packet = Bytes::from_static(&[
            0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 64, 0x11, 0x00, 0x00, 10, 0, 0, 1, 10,
            0, 0, 2,
        ]);
        let datagram = build_flow_datagram(&flow_prefix, &packet).unwrap();
        assert_eq!(datagram[flow_prefix.len() + 8], 63);
    }

    #[test]
    fn effective_inner_mtu_clamps_to_writable_datagram_budget() {
        assert_eq!(effective_inner_mtu(Some(1250), 2, 1340), 1248);
        assert_eq!(effective_inner_mtu(Some(1344), 2, 1340), 1340);
        assert_eq!(effective_inner_mtu(Some(2), 2, 1340), 1340);
        assert_eq!(effective_inner_mtu(None, 2, 1340), 1340);
    }
}
