use anyhow::{bail, Result};
use bytes::{Bytes, BytesMut};
use futures::{Future, Sink, Stream};
use octets::Octets;
use quiche::h3::NameValue;
use ring::rand::SecureRandom;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::str::FromStr;
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

pub(crate) const DEFAULT_INBOUND_QUEUE_CAPACITY: usize = 4096;
pub(crate) const DEFAULT_OUTBOUND_QUEUE_CAPACITY: usize = 4096;
const OUTBOUND_QUEUE_MAX_AGE: Duration = Duration::from_millis(100);
const PACING_BURST_HORIZON: Duration = Duration::from_millis(2);
const QUICHE_DGRAM_RECV_QUEUE_LEN: usize = 4096;
const QUICHE_DGRAM_SEND_QUEUE_LEN: usize = 1024;
const UDP_RECV_MAX_PER_POLL: usize = 128;
const INBOUND_SLAB_CAPACITY: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const UDP_RECV_GRO_SLOTS: usize = 8;
#[cfg(target_os = "linux")]
const UDP_RECV_GRO_SLOT_CAP: usize = 65536;
#[cfg(target_os = "linux")]
const UDP_RECV_PLAIN_SLOTS: usize = 32;
#[cfg(target_os = "linux")]
const UDP_RECV_PLAIN_SLOT_CAP: usize = 2048;
#[cfg(target_os = "linux")]
const UDP_RECV_CMSG_SIZE: usize = 64;
#[cfg(target_os = "linux")]
const UDP_GRO_OPT: libc::c_int = 104;
#[cfg(target_os = "linux")]
const CACHE_LINE_BYTES: usize = 64;
#[cfg(target_os = "linux")]
const PAGE_BYTES: usize = 4096;
const BBR2_LOSS_THRESHOLD: f32 = 0.20;
const BBR2_MAX_PROBE_UP_QUEUE_ROUNDS: usize = 8;
const BBR2_PROBE_UP_PACING_GAIN: f32 = 1.5;
const BBR2_PROBE_BW_CWND_GAIN: f32 = 3.0;
const BBR2_PROBE_BW_UP_CWND_GAIN: f32 = 3.5;
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CongestionControl {
    #[default]
    Cubic,
    #[serde(alias = "bbr", alias = "bbr2_gcongestion")]
    Bbr2,
    Reno,
}

impl CongestionControl {
    pub const fn to_quiche(self) -> quiche::CongestionControlAlgorithm {
        match self {
            Self::Cubic => quiche::CongestionControlAlgorithm::CUBIC,
            Self::Bbr2 => quiche::CongestionControlAlgorithm::Bbr2Gcongestion,
            Self::Reno => quiche::CongestionControlAlgorithm::Reno,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cubic => "cubic",
            Self::Bbr2 => "bbr2",
            Self::Reno => "reno",
        }
    }
}

impl fmt::Display for CongestionControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for CongestionControl {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "cubic" => Ok(Self::Cubic),
            "bbr2" | "bbr" | "bbr2_gcongestion" => Ok(Self::Bbr2),
            "reno" => Ok(Self::Reno),
            _ => Err(format!(
                "unsupported congestion control algorithm '{s}' (expected cubic, bbr2, or reno)"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MasqueProtocol {
    #[default]
    #[serde(alias = "http3", alias = "quic")]
    H3,
    #[serde(alias = "http2", alias = "tcp")]
    H2,
}

impl MasqueProtocol {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::H3 => "h3",
            Self::H2 => "h2",
        }
    }
}

impl fmt::Display for MasqueProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for MasqueProtocol {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "h3" | "http3" | "quic" => Ok(Self::H3),
            "h2" | "http2" | "tcp" => Ok(Self::H2),
            _ => Err(format!(
                "unsupported MASQUE protocol '{s}' (expected h3 or h2)"
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PacketSessionConfig {
    pub endpoint: SocketAddr,
    pub bind: Option<SocketAddr>,
    pub sni: String,
    pub keepalive_period: Duration,
    pub mtu: u32,
    pub congestion_control: CongestionControl,
    pub protocol: MasqueProtocol,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MasqueSessionStats {
    pub protocol: MasqueProtocol,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub sent_packets: u64,
    pub recv_packets: u64,
    pub lost_packets: u64,
    pub spurious_lost_packets: u64,
    pub dgram_sent: u64,
    pub dgram_recv: u64,
    pub dgram_lost: u64,
    pub sent_bytes: u64,
    pub recv_bytes: u64,
    pub cwnd_bytes: u64,
    pub rtt_ms: f64,
    pub min_rtt_ms: Option<f64>,
    pub delivery_rate_bps: u64,
    pub max_bandwidth_bps: Option<u64>,
    pub outbound_queue_len: usize,
    pub outbound_queue_drops: u64,
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

use crate::h2_session::H2PacketStream;

pub struct MasquePacketStream {
    inner: PacketStreamInner,
}

enum PacketStreamInner {
    H3(Box<H3PacketStream>),
    H2(Box<H2PacketStream>),
}

impl MasquePacketStream {
    pub async fn connect(config: Arc<Config>, session_cfg: PacketSessionConfig) -> Result<Self> {
        let inner = match session_cfg.protocol {
            MasqueProtocol::H3 => {
                PacketStreamInner::H3(Box::new(H3PacketStream::connect(config, session_cfg).await?))
            }
            MasqueProtocol::H2 => {
                PacketStreamInner::H2(Box::new(H2PacketStream::connect(config, session_cfg).await?))
            }
        };
        Ok(Self { inner })
    }

    pub fn state(&self) -> PacketSessionState {
        match &self.inner {
            PacketStreamInner::H3(s) => s.state(),
            PacketStreamInner::H2(s) => s.state(),
        }
    }

    pub fn stats(&self) -> MasqueSessionStats {
        match &self.inner {
            PacketStreamInner::H3(s) => s.stats(),
            PacketStreamInner::H2(s) => s.stats(),
        }
    }

    pub async fn close(&mut self) -> io::Result<()> {
        match &mut self.inner {
            PacketStreamInner::H3(s) => s.close().await,
            PacketStreamInner::H2(s) => {
                s.close_now();
                Ok(())
            }
        }
    }
}

impl Stream for MasquePacketStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match &mut self.inner {
            PacketStreamInner::H3(s) => Pin::new(&mut **s).poll_next(cx),
            PacketStreamInner::H2(s) => Pin::new(&mut **s).poll_next(cx),
        }
    }
}

impl Sink<Bytes> for MasquePacketStream {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            PacketStreamInner::H3(s) => Pin::new(&mut **s).poll_ready(cx),
            PacketStreamInner::H2(s) => Pin::new(&mut **s).poll_ready(cx),
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> io::Result<()> {
        match &mut self.inner {
            PacketStreamInner::H3(s) => Pin::new(&mut **s).start_send(item),
            PacketStreamInner::H2(s) => Pin::new(&mut **s).start_send(item),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            PacketStreamInner::H3(s) => Pin::new(&mut **s).poll_flush(cx),
            PacketStreamInner::H2(s) => Pin::new(&mut **s).poll_flush(cx),
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.inner {
            PacketStreamInner::H3(s) => Pin::new(&mut **s).poll_close(cx),
            PacketStreamInner::H2(s) => Pin::new(&mut **s).poll_close(cx),
        }
    }
}

struct H3PacketStream {
    socket: tokio::net::UdpSocket,
    conn: quiche::Connection,
    h3_conn: quiche::h3::Connection,
    connect_stream_id: u64,
    flow_id: u64,
    flow_prefix: Vec<u8>,
    mtu: u16,
    outbound_queue: VecDeque<(Instant, Bytes)>,
    outbound_queue_drops: u64,
    inbound_slab: BytesMut,
    #[cfg(target_os = "linux")]
    recv_batch: RecvMmsgGroBuf,
    inbound_queue: VecDeque<Bytes>,
    out: Vec<u8>,
    buf: Vec<u8>,
    local_addr: SocketAddr,
    endpoint: SocketAddr,
    state: PacketSessionState,
    timeout: Pin<Box<Sleep>>,
    has_timeout: bool,
    pacing_timer: Pin<Box<Sleep>>,
    pending_send: Option<PendingUdpSend>,
    terminal_error: Option<String>,
    emitted_terminal_error: bool,
}

#[cfg(target_os = "linux")]
fn recv_slot_stride(slot_cap: usize) -> usize {
    let cap = slot_cap.max(1);
    let aligned = (cap + (CACHE_LINE_BYTES - 1)) & !(CACHE_LINE_BYTES - 1);
    if aligned % PAGE_BYTES == 0 {
        aligned + CACHE_LINE_BYTES
    } else {
        aligned
    }
}

#[cfg(target_os = "linux")]
struct RecvMmsgGroBuf {
    gro_enabled: bool,
    slots: usize,
    slot_cap: usize,
    stride: usize,
    slab: Box<[u8]>,
    cmsgs: Box<[u8]>,
    _iovecs: Box<[libc::iovec]>,
    headers: Box<[libc::mmsghdr]>,
}

#[cfg(target_os = "linux")]
// SAFETY: All raw pointers inside `headers`/`_iovecs` target exclusively owned boxed slices
// (`slab`, `cmsgs`, `_iovecs`) whose heap addresses remain fixed across moves.
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for RecvMmsgGroBuf {}

#[cfg(target_os = "linux")]
impl RecvMmsgGroBuf {
    fn new(gro_enabled: bool) -> Self {
        let (slots, slot_cap, cmsg_size) = if gro_enabled {
            (UDP_RECV_GRO_SLOTS, UDP_RECV_GRO_SLOT_CAP, UDP_RECV_CMSG_SIZE)
        } else {
            (UDP_RECV_PLAIN_SLOTS, UDP_RECV_PLAIN_SLOT_CAP, 0)
        };
        let stride = recv_slot_stride(slot_cap);
        let mut slab = vec![0_u8; slots * stride].into_boxed_slice();
        let mut cmsgs = vec![0_u8; slots * cmsg_size].into_boxed_slice();
        let mut iovecs = Vec::with_capacity(slots);
        for i in 0..slots {
            let ptr = unsafe { slab.as_mut_ptr().add(i * stride) };
            iovecs.push(libc::iovec {
                iov_base: ptr.cast(),
                iov_len: slot_cap,
            });
        }
        let mut iovecs = iovecs.into_boxed_slice();
        let mut headers = Vec::with_capacity(slots);
        for i in 0..slots {
            let mut hdr: libc::mmsghdr = unsafe { std::mem::zeroed() };
            hdr.msg_hdr.msg_iov = unsafe { iovecs.as_mut_ptr().add(i) };
            hdr.msg_hdr.msg_iovlen = 1;
            if cmsg_size > 0 {
                hdr.msg_hdr.msg_control = unsafe { cmsgs.as_mut_ptr().add(i * cmsg_size).cast() };
                hdr.msg_hdr.msg_controllen = cmsg_size;
            }
            headers.push(hdr);
        }
        Self {
            gro_enabled,
            slots,
            slot_cap,
            stride,
            slab,
            cmsgs,
            _iovecs: iovecs,
            headers: headers.into_boxed_slice(),
        }
    }

    fn try_enable_udp_gro(socket: &tokio::net::UdpSocket) -> bool {
        use std::os::fd::AsRawFd;
        let enable: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_UDP,
                UDP_GRO_OPT,
                std::ptr::addr_of!(enable).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        ret == 0
    }

    fn try_recv_batch(&mut self, socket: &tokio::net::UdpSocket) -> io::Result<Option<usize>> {
        use std::os::fd::AsRawFd;
        use tokio::io::Interest;
        let slots = self.slots;
        let gro_enabled = self.gro_enabled;
        match socket.try_io(Interest::READABLE, || {
            let fd = socket.as_raw_fd();
            for i in 0..slots {
                self.headers[i].msg_len = 0;
                self.headers[i].msg_hdr.msg_flags = 0;
                if gro_enabled {
                    self.headers[i].msg_hdr.msg_control =
                        unsafe { self.cmsgs.as_mut_ptr().add(i * UDP_RECV_CMSG_SIZE).cast() };
                    self.headers[i].msg_hdr.msg_controllen = UDP_RECV_CMSG_SIZE;
                }
            }
            let n = unsafe {
                libc::recvmmsg(
                    fd,
                    self.headers.as_mut_ptr(),
                    slots as u32,
                    libc::MSG_DONTWAIT,
                    std::ptr::null_mut(),
                )
            };
            if n < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(n) => Ok(Some(n)),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn slot_mut(&mut self, idx: usize) -> (&mut [u8], usize) {
        let total_len = (self.headers[idx].msg_len as usize).min(self.slot_cap);
        let mut gso_size = 0usize;
        if self.gro_enabled {
            unsafe {
                let hdr = &self.headers[idx].msg_hdr;
                let mut cmsg = libc::CMSG_FIRSTHDR(hdr);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::IPPROTO_UDP && (*cmsg).cmsg_type == UDP_GRO_OPT {
                        let mut raw = [0_u8; 2];
                        std::ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsg), raw.as_mut_ptr(), 2);
                        gso_size = usize::from(u16::from_ne_bytes(raw));
                        break;
                    }
                    cmsg = libc::CMSG_NXTHDR(hdr, cmsg);
                }
            }
        }
        let start = idx * self.stride;
        (&mut self.slab[start..start + total_len], gso_size)
    }
}

struct PendingUdpSend {
    len: usize,
    to: SocketAddr,
    at: Instant,
}

impl H3PacketStream {
    pub async fn connect(config: Arc<Config>, session_cfg: PacketSessionConfig) -> Result<Self> {
        let tls_material = tls::prepare_tls_material(config.as_ref())?;
        let mut quic_config = build_quic_config(
            &tls_material,
            session_cfg.mtu,
            session_cfg.congestion_control,
        )?;

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

        #[cfg(target_os = "linux")]
        let gro_enabled = RecvMmsgGroBuf::try_enable_udp_gro(&socket);
        let mut stream = Self {
            socket,
            conn,
            h3_conn,
            connect_stream_id: stream_id,
            flow_id,
            flow_prefix: build_flow_prefix(flow_id),
            mtu: session_cfg.mtu.min(u32::from(u16::MAX)) as u16,
            outbound_queue: VecDeque::new(),
            outbound_queue_drops: 0,
            inbound_slab: BytesMut::with_capacity(INBOUND_SLAB_CAPACITY),
            #[cfg(target_os = "linux")]
            recv_batch: RecvMmsgGroBuf::new(gro_enabled),
            inbound_queue: VecDeque::new(),
            out,
            buf,
            local_addr,
            endpoint: session_cfg.endpoint,
            state: PacketSessionState::Ready,
            timeout: Box::pin(tokio::time::sleep(Duration::from_millis(0))),
            has_timeout: false,
            pacing_timer: Box::pin(tokio::time::sleep(Duration::from_millis(0))),
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

    pub fn stats(&self) -> MasqueSessionStats {
        let st = self.conn.stats();
        let path = self.conn.path_stats().next();
        MasqueSessionStats {
            protocol: MasqueProtocol::H3,
            local_addr: self.local_addr,
            peer_addr: self.endpoint,
            sent_packets: st.sent as u64,
            recv_packets: st.recv as u64,
            lost_packets: st.lost as u64,
            spurious_lost_packets: st.spurious_lost as u64,
            dgram_sent: st.dgram_sent as u64,
            dgram_recv: st.dgram_recv as u64,
            dgram_lost: path.as_ref().map_or(0, |p| p.dgram_lost as u64),
            sent_bytes: st.sent_bytes,
            recv_bytes: st.recv_bytes,
            cwnd_bytes: path.as_ref().map_or(0, |p| p.cwnd as u64),
            rtt_ms: path.as_ref().map_or(0.0, |p| p.rtt.as_secs_f64() * 1000.0),
            min_rtt_ms: path
                .as_ref()
                .and_then(|p| p.min_rtt)
                .map(|d| d.as_secs_f64() * 1000.0),
            delivery_rate_bps: path
                .as_ref()
                .map_or(0, |p| p.delivery_rate.saturating_mul(8)),
            max_bandwidth_bps: path
                .as_ref()
                .and_then(|p| p.max_bandwidth)
                .map(|b| b.saturating_mul(8)),
            outbound_queue_len: self.outbound_queue.len(),
            outbound_queue_drops: self.outbound_queue_drops,
        }
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
                &mut self.outbound_queue_drops,
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
        if self.inbound_queue.len() >= DEFAULT_INBOUND_QUEUE_CAPACITY {
            return Poll::Pending;
        }
        let mut received = false;
        let mut total_cnt = 0usize;

        loop {
            if total_cnt >= UDP_RECV_MAX_PER_POLL {
                if received {
                    self.reset_timeout();
                }
                return Poll::Ready(Ok(true));
            }

            match self.socket.poll_recv_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {
                    if received {
                        self.reset_timeout();
                        return Poll::Ready(Ok(true));
                    }
                    return Poll::Pending;
                }
            }

            let recv_info = quiche::RecvInfo {
                to: self.local_addr,
                from: self.endpoint,
            };

            #[cfg(target_os = "linux")]
            loop {
                if total_cnt >= UDP_RECV_MAX_PER_POLL {
                    break;
                }
                match self.recv_batch.try_recv_batch(&self.socket)? {
                    Some(0) | None => break,
                    Some(n) => {
                        for i in 0..n {
                            let (buf, gso_size) = self.recv_batch.slot_mut(i);
                            if gso_size > 0 && buf.len() > gso_size {
                                for chunk in buf.chunks_mut(gso_size) {
                                    if let Err(error) = self.conn.recv(chunk, recv_info) {
                                        log::debug!("quic recv error: {error}");
                                    }
                                    total_cnt += 1;
                                }
                            } else {
                                if let Err(error) = self.conn.recv(buf, recv_info) {
                                    log::debug!("quic recv error: {error}");
                                }
                                total_cnt += 1;
                            }
                        }
                        received = true;
                    }
                }
            }
            #[cfg(not(target_os = "linux"))]
            loop {
                if total_cnt >= UDP_RECV_MAX_PER_POLL {
                    break;
                }
                match self.socket.try_recv(&mut self.buf) {
                    Ok(len) => {
                        if let Err(error) = self.conn.recv(&mut self.buf[..len], recv_info) {
                            log::debug!("quic recv error: {error}");
                        }
                        total_cnt += 1;
                        received = true;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
        }
    }

    fn poll_flush_conn_send(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let mut flushed = false;
        let mut generated = false;
        let mut cached_now: Option<Instant> = None;

        loop {
            if self.pending_send.is_none() {
                let (write, send_info) = match self.conn.send(&mut self.out) {
                    Ok(result) => result,
                    Err(quiche::Error::Done) => {
                        if generated {
                            self.reset_timeout();
                        }
                        return Poll::Ready(Ok(flushed));
                    }
                    Err(error) => {
                        if generated {
                            self.reset_timeout();
                        }
                        return Poll::Ready(Err(io::Error::other(error.to_string())));
                    }
                };

                self.pending_send = Some(PendingUdpSend {
                    len: write,
                    to: send_info.to,
                    at: Instant::from_std(send_info.at),
                });
                generated = true;
            }

            let send_at = self.pending_send.as_ref().unwrap().at;
            // quiche 0.30 仅 BBR2 的 gcongestion recovery 返回晚于 now 的 send_info.at；Cubic/Reno 不会等待。
            if !self.conn.is_closed() {
                let now = match cached_now {
                    Some(now) if send_at <= now + PACING_BURST_HORIZON => now,
                    _ => {
                        let fresh = Instant::now();
                        cached_now = Some(fresh);
                        fresh
                    }
                };
                if poll_pacing_wait(&mut self.pacing_timer, send_at, now, cx).is_pending() {
                    if generated {
                        self.reset_timeout();
                    }
                    return if flushed {
                        Poll::Ready(Ok(true))
                    } else {
                        Poll::Pending
                    };
                }
            }

            match self.socket.poll_send_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(error)) => {
                    if generated {
                        self.reset_timeout();
                    }
                    return Poll::Ready(Err(error));
                }
                Poll::Pending => {
                    if generated {
                        self.reset_timeout();
                    }
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
            if self.inbound_queue.len() >= DEFAULT_INBOUND_QUEUE_CAPACITY {
                return Ok(progressed);
            }

            let Some(next_len) = self.conn.dgram_recv_front_len() else {
                return Ok(progressed);
            };
            if self.inbound_slab.capacity() < next_len {
                self.inbound_slab = BytesMut::with_capacity(INBOUND_SLAB_CAPACITY.max(next_len));
            }
            let start = self.inbound_slab.len();
            self.inbound_slab.resize(start + next_len, 0);
            match self.conn.dgram_recv(&mut self.inbound_slab[start..start + next_len]) {
                Ok(n) => {
                    self.inbound_slab.truncate(start + n);
                    let dgram = self.inbound_slab.split().freeze();
                    progressed = true;
                    if let Some(offset) = parse_datagram_offset(&dgram, self.flow_id) {
                        let packet = dgram.slice(offset..);
                        if packet::validate_incoming(packet.as_ref()).is_ok() {
                            self.inbound_queue.push_back(packet);
                        }
                    }
                }
                Err(quiche::Error::Done) => {
                    self.inbound_slab.truncate(start);
                    return Ok(progressed);
                }
                Err(error) => {
                    self.inbound_slab.truncate(start);
                    log::debug!("dgram recv error: {error}");
                    return Ok(progressed);
                }
            }
        }
    }
}

impl Stream for H3PacketStream {
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

impl Sink<Bytes> for H3PacketStream {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.state == PacketSessionState::Closed {
            return Poll::Ready(Err(self.closed_io_error()));
        }

        if self.terminal_error.is_some() {
            return Poll::Ready(Err(self.terminal_io_error()));
        }

        if self.outbound_queue.len() >= DEFAULT_OUTBOUND_QUEUE_CAPACITY {
            if let Poll::Ready(Err(error)) = self.poll_drive(cx) {
                self.set_terminal_error(error.to_string());
                return Poll::Ready(Err(error));
            }
        }

        // 不可靠 datagram 隧道满队时不向上游反压（避免上层桥接继续囤包），由 start_send 丢弃最旧包。
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> io::Result<()> {
        if self.state == PacketSessionState::Closed {
            return Err(self.closed_io_error());
        }

        if self.terminal_error.is_some() {
            return Err(self.terminal_io_error());
        }

        let now = Instant::now();
        let dropped = prune_outbound_queue(
            &mut self.outbound_queue,
            now,
            DEFAULT_OUTBOUND_QUEUE_CAPACITY.saturating_sub(1),
        );
        self.outbound_queue_drops = self.outbound_queue_drops.saturating_add(dropped as u64);
        self.outbound_queue.push_back((now, item));
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

fn poll_pacing_wait(
    pacing_timer: &mut Pin<Box<Sleep>>,
    send_at: Instant,
    now: Instant,
    cx: &mut Context<'_>,
) -> Poll<()> {
    // 跳过 <=2ms 的微小间隔，避免逐包触发 1ms 时间轮 Sleep 过睡并被 quiche pacer 累加限速。
    if send_at.saturating_duration_since(now) > PACING_BURST_HORIZON {
        if pacing_timer.deadline() != send_at {
            pacing_timer.as_mut().reset(send_at);
        }
        if pacing_timer.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
    }
    Poll::Ready(())
}

fn build_quic_config(
    tls_material: &tls::TlsMaterial,
    mtu: u32,
    cc: CongestionControl,
) -> Result<quiche::Config> {
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
    quic_config.enable_dgram(
        true,
        QUICHE_DGRAM_RECV_QUEUE_LEN,
        QUICHE_DGRAM_SEND_QUEUE_LEN,
    );
    quic_config.enable_pacing(true);
    quic_config.set_cc_algorithm(cc.to_quiche());
    if cc == CongestionControl::Bbr2 {
        // 1. 首次假丢包后关闭 MAX_PACKET_THRESHOLD=20，改用自适应时间阈值抗高乱序（避免误触发 ProbeBW 0.7^k 降速）；
        // 2. 放宽 ProbeBW 队列轮数、上探 pacing_gain 与窗口增益，避免常态 RTT≈2×min_rtt 时 ProbeUp 2 轮即退出且 Cruise 被 cwnd 卡死；
        // 注：不启用实验性 InflightReduction，其在 quiche 0.30 Startup 丢单包时会锁死 bandwidth_lo。
        quic_config.set_enable_relaxed_loss_threshold(true);
        quic_config.set_custom_bbr_params(quiche::BbrParams {
            loss_threshold: Some(BBR2_LOSS_THRESHOLD),
            max_probe_up_queue_rounds: Some(BBR2_MAX_PROBE_UP_QUEUE_ROUNDS),
            probe_bw_probe_up_pacing_gain: Some(BBR2_PROBE_UP_PACING_GAIN),
            probe_bw_cwnd_gain: Some(BBR2_PROBE_BW_CWND_GAIN),
            probe_bw_up_cwnd_gain: Some(BBR2_PROBE_BW_UP_CWND_GAIN),
            ..Default::default()
        });
    }

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

pub(crate) fn prune_outbound_queue(
    queue: &mut VecDeque<(Instant, Bytes)>,
    now: Instant,
    max_len: usize,
) -> usize {
    let mut dropped = 0_usize;
    while let Some((enqueued_at, _)) = queue.front() {
        if now.saturating_duration_since(*enqueued_at) > OUTBOUND_QUEUE_MAX_AGE
            || queue.len() > max_len
        {
            let _ = queue.pop_front();
            dropped += 1;
        } else {
            break;
        }
    }
    dropped
}

fn flush_pending_queue(
    conn: &mut quiche::Connection,
    flow_prefix: &[u8],
    mtu: u16,
    queue: &mut VecDeque<(Instant, Bytes)>,
    outbound_queue_drops: &mut u64,
    inbound_queue: &mut VecDeque<Bytes>,
) -> bool {
    let dropped = prune_outbound_queue(queue, Instant::now(), usize::MAX);
    *outbound_queue_drops = outbound_queue_drops.saturating_add(dropped as u64);
    let mut progressed = dropped > 0;

    while let Some((_, packet)) = queue.front() {
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
                    let Some((_, packet)) = queue.pop_front() else {
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
                    if inbound_queue.len() < DEFAULT_INBOUND_QUEUE_CAPACITY {
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

    #[test]
    fn masque_protocol_parse_and_serde() {
        assert_eq!(MasqueProtocol::default(), MasqueProtocol::H3);
        assert_eq!("h3".parse::<MasqueProtocol>().unwrap(), MasqueProtocol::H3);
        assert_eq!("http3".parse::<MasqueProtocol>().unwrap(), MasqueProtocol::H3);
        assert_eq!("quic".parse::<MasqueProtocol>().unwrap(), MasqueProtocol::H3);
        assert_eq!("h2".parse::<MasqueProtocol>().unwrap(), MasqueProtocol::H2);
        assert_eq!("HTTP2".parse::<MasqueProtocol>().unwrap(), MasqueProtocol::H2);
        assert_eq!("tcp".parse::<MasqueProtocol>().unwrap(), MasqueProtocol::H2);
        assert!("ws".parse::<MasqueProtocol>().is_err());

        let h2: MasqueProtocol = serde_json::from_str(r#""http2""#).unwrap();
        assert_eq!(h2, MasqueProtocol::H2);
        assert_eq!(serde_json::to_string(&h2).unwrap(), r#""h2""#);
    }

    #[test]
    fn congestion_control_parse_and_serde() {
        assert_eq!(CongestionControl::default(), CongestionControl::Cubic);
        assert_eq!("cubic".parse::<CongestionControl>().unwrap(), CongestionControl::Cubic);
        assert_eq!("BBR2".parse::<CongestionControl>().unwrap(), CongestionControl::Bbr2);
        assert_eq!("bbr".parse::<CongestionControl>().unwrap(), CongestionControl::Bbr2);
        assert_eq!(
            "bbr2_gcongestion".parse::<CongestionControl>().unwrap(),
            CongestionControl::Bbr2
        );
        assert_eq!("reno".parse::<CongestionControl>().unwrap(), CongestionControl::Reno);
        assert!("westwood".parse::<CongestionControl>().is_err());

        let bbr2: CongestionControl = serde_json::from_str("\"bbr\"").unwrap();
        assert_eq!(bbr2, CongestionControl::Bbr2);
        assert_eq!(serde_json::to_string(&bbr2).unwrap(), "\"bbr2\"");
    }

    #[tokio::test]
    async fn pacing_wait_arms_rearms_and_releases_on_deadline() {
        let mut timer = Box::pin(tokio::time::sleep(Duration::from_millis(0)));
        let waker = futures::task::noop_waker_ref();
        let mut cx = Context::from_waker(waker);

        let now = Instant::now();
        assert!(poll_pacing_wait(&mut timer, now, now, &mut cx).is_ready());
        assert!(poll_pacing_wait(&mut timer, now + PACING_BURST_HORIZON, now, &mut cx).is_ready());

        let first_target = now + Duration::from_secs(10);
        assert!(poll_pacing_wait(&mut timer, first_target, now, &mut cx).is_pending());
        assert_eq!(timer.deadline(), first_target);

        let second_target = now + Duration::from_secs(20);
        assert!(poll_pacing_wait(&mut timer, second_target, now, &mut cx).is_pending());
        assert_eq!(timer.deadline(), second_target);

        assert!(poll_pacing_wait(&mut timer, second_target, second_target, &mut cx).is_ready());
    }

    #[test]
    fn prune_outbound_queue_drops_expired_and_enforces_capacity() {
        let base = Instant::now();
        let mut queue = VecDeque::from([
            (base, Bytes::from_static(b"expired")),
            (base + Duration::from_millis(60), Bytes::from_static(b"fresh-1")),
            (base + Duration::from_millis(90), Bytes::from_static(b"fresh-2")),
            (base + Duration::from_millis(100), Bytes::from_static(b"fresh-3")),
        ]);

        let now = base + Duration::from_millis(120);
        assert_eq!(prune_outbound_queue(&mut queue, now, 2), 2);
        let remaining: Vec<&[u8]> = queue.iter().map(|(_, p)| p.as_ref()).collect();
        assert_eq!(remaining, vec![b"fresh-2".as_slice(), b"fresh-3".as_slice()]);
        assert_eq!(prune_outbound_queue(&mut queue, now, 2), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recv_slot_stride_avoids_page_multiples() {
        assert_eq!(recv_slot_stride(2048), 2048);
        assert_eq!(recv_slot_stride(4096), 4096 + 64);
        assert_eq!(recv_slot_stride(65536), 65536 + 64);
        assert_eq!(recv_slot_stride(1500), 1536);
        assert_eq!(recv_slot_stride(65536) % PAGE_BYTES, CACHE_LINE_BYTES);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn recvmmsg_gro_buf_receives_batch_on_loopback() {
        let rx = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rx_addr = rx.local_addr().unwrap();
        let tx = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let gro_enabled = RecvMmsgGroBuf::try_enable_udp_gro(&rx);
        let mut batch = RecvMmsgGroBuf::new(gro_enabled);

        let payloads: [&[u8]; 3] = [b"pkt-one", b"pkt-two-22", b"pkt-three-333"];
        for p in payloads {
            tx.send_to(p, rx_addr).await.unwrap();
        }

        let mut received = Vec::new();
        while received.len() < payloads.len() {
            rx.readable().await.unwrap();
            if let Some(n) = batch.try_recv_batch(&rx).unwrap() {
                for i in 0..n {
                    let (buf, gso_size) = batch.slot_mut(i);
                    if gso_size > 0 && buf.len() > gso_size {
                        for chunk in buf.chunks(gso_size) {
                            received.push(chunk.to_vec());
                        }
                    } else {
                        received.push(buf.to_vec());
                    }
                }
            }
        }

        assert_eq!(received.len(), payloads.len());
        for (got, expected) in received.iter().zip(payloads.iter()) {
            assert_eq!(got.as_slice(), *expected);
        }
    }
}
