use anyhow::{bail, Context as _, Result};
use bytes::{BufMut, Bytes, BytesMut};
use futures::{Future, Sink, Stream};
use h2::client::{Builder as H2Builder, Connection as H2Connection, SendRequest};
use h2::{Ping, PingPong, RecvStream, SendStream};
use http::{HeaderValue, Method, Request, Uri};
use octets::OctetsMut;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, WebPkiSupportedAlgorithms};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use socket2::{SockRef, TcpKeepalive};
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpSocket, TcpStream};
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tokio::time::{Instant, Sleep};
use tokio_rustls::TlsConnector;

use crate::config::Config;
use crate::packet;
use crate::packet_session::{
    prune_outbound_queue, CongestionControl, PacketSessionConfig, PacketSessionState, CONNECT_TIMEOUT,
    DEFAULT_INBOUND_QUEUE_CAPACITY, DEFAULT_OUTBOUND_QUEUE_CAPACITY,
};
use crate::tls::{self, TlsDerMaterial};

const H2_CONNECT_AUTHORITY: &str = "cloudflareaccess.com:443";
const H2_DATAGRAM_CAPSULE_TYPE: u64 = 0;
const H2_INITIAL_STREAM_WINDOW_SIZE: u32 = 8 * 1024 * 1024;
const H2_INITIAL_CONN_WINDOW_SIZE: u32 = 16 * 1024 * 1024;
const H2_MAX_FRAME_SIZE: u32 = 65_536;
const H2_SEND_BUFFER_SIZE: usize = 32 * 1024;
const H2_COALESCE_LIMIT: usize = 16 * 1024;
#[cfg(target_os = "linux")]
const H2_TCP_NOTSENT_LOWAT: libc::c_int = 16 * 1024;
const MAX_CAPSULE_PAYLOAD_LEN: usize = 65_536;
const H2_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const H2_MIN_PING_INTERVAL: Duration = Duration::from_secs(10);
const H2_PING_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) struct H2PacketStream {
    send_stream: SendStream<Bytes>,
    recv_stream: RecvStream,
    _send_request: SendRequest<Bytes>,
    conn_task: JoinHandle<()>,
    conn_err_rx: Option<oneshot::Receiver<String>>,
    outbound_queue: VecDeque<(Instant, Bytes)>,
    inbound_queue: VecDeque<Bytes>,
    pending_wire: BytesMut,
    recv_buf: BytesMut,
    state: PacketSessionState,
    idle_timeout: Pin<Box<Sleep>>,
    terminal_error: Option<String>,
    emitted_terminal_error: bool,
}

impl Drop for H2PacketStream {
    fn drop(&mut self) {
        self.conn_task.abort();
    }
}

impl H2PacketStream {
    pub(crate) async fn connect(
        config: Arc<Config>,
        session_cfg: PacketSessionConfig,
    ) -> Result<Self> {
        let tls_der = tls::prepare_tls_der(config.as_ref())?;
        let tls_config = build_rustls_client_config(&tls_der)?;
        let server_name = ServerName::try_from(session_cfg.sni.clone())
            .map_err(|e| anyhow::anyhow!("invalid H2 TLS SNI '{}': {e}", session_cfg.sni))?;

        tokio::time::timeout(CONNECT_TIMEOUT, async {
            let tcp = connect_tcp(session_cfg.endpoint, session_cfg.bind, session_cfg.congestion_control).await?;
            let connector = TlsConnector::from(tls_config);
            let tls_stream = connector
                .connect(server_name, tcp)
                .await
                .context("MASQUE H2 TLS handshake failed")?;

            Self::handshake_over_io(tls_stream, session_cfg.keepalive_period).await
        })
        .await
        .map_err(|_| anyhow::anyhow!("MASQUE H2 connection timed out after {CONNECT_TIMEOUT:?}"))?
    }

    async fn handshake_over_io<IO>(io: IO, keepalive_period: Duration) -> Result<Self>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (send_request, mut connection) = H2Builder::new()
            .initial_window_size(H2_INITIAL_STREAM_WINDOW_SIZE)
            .initial_connection_window_size(H2_INITIAL_CONN_WINDOW_SIZE)
            .max_frame_size(H2_MAX_FRAME_SIZE)
            .max_send_buffer_size(H2_SEND_BUFFER_SIZE)
            .enable_push(false)
            .handshake::<IO, Bytes>(io)
            .await
            .context("MASQUE H2 handshake failed")?;

        let ping_pong = connection.ping_pong();
        let (conn_err_tx, conn_err_rx) = oneshot::channel();
        let ping_interval = keepalive_period.max(H2_MIN_PING_INTERVAL);
        let conn_task = tokio::spawn(run_h2_connection(
            connection,
            ping_pong,
            ping_interval,
            conn_err_tx,
        ));

        let mut send_request = match send_request.ready().await {
            Ok(sr) => sr,
            Err(e) => {
                conn_task.abort();
                return Err(anyhow::anyhow!("MASQUE H2 client not ready: {e}"));
            }
        };

        let request = build_connect_ip_request()?;
        let (response_fut, send_stream) = match send_request.send_request(request, false) {
            Ok(pair) => pair,
            Err(e) => {
                conn_task.abort();
                return Err(anyhow::anyhow!("failed to send H2 CONNECT-IP request: {e}"));
            }
        };

        let response = match response_fut.await {
            Ok(resp) => resp,
            Err(e) => {
                conn_task.abort();
                return Err(anyhow::anyhow!("H2 CONNECT-IP response failed: {e}"));
            }
        };

        if !response.status().is_success() {
            conn_task.abort();
            bail!("H2 CONNECT-IP rejected with HTTP {}", response.status());
        }

        let recv_stream = response.into_body();
        let now = Instant::now();
        Ok(Self {
            send_stream,
            recv_stream,
            _send_request: send_request,
            conn_task,
            conn_err_rx: Some(conn_err_rx),
            outbound_queue: VecDeque::with_capacity(DEFAULT_OUTBOUND_QUEUE_CAPACITY),
            inbound_queue: VecDeque::with_capacity(DEFAULT_INBOUND_QUEUE_CAPACITY),
            pending_wire: BytesMut::with_capacity(H2_COALESCE_LIMIT),
            recv_buf: BytesMut::with_capacity(16 * 1024),
            state: PacketSessionState::Ready,
            idle_timeout: Box::pin(tokio::time::sleep_until(now + H2_IDLE_TIMEOUT)),
            terminal_error: None,
            emitted_terminal_error: false,
        })
    }

    pub(crate) const fn state(&self) -> PacketSessionState {
        self.state
    }

    pub(crate) fn close_now(&mut self) {
        self.send_stream.send_reset(h2::Reason::NO_ERROR);
        self.conn_task.abort();
        self.state = PacketSessionState::Closed;
        self.emitted_terminal_error = true;
    }

    fn set_terminal_error(&mut self, message: impl Into<String>) {
        if self.terminal_error.is_none() {
            self.terminal_error = Some(message.into());
        }
        self.state = PacketSessionState::Closed;
        self.conn_task.abort();
    }

    fn terminal_io_error(&self) -> io::Error {
        io::Error::other(
            self.terminal_error
                .as_deref()
                .unwrap_or("MASQUE H2 session closed"),
        )
    }

    fn reset_idle_timeout(&mut self) {
        self.idle_timeout
            .as_mut()
            .reset(Instant::now() + H2_IDLE_TIMEOUT);
    }

    fn poll_connection_health(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if let Some(rx) = &mut self.conn_err_rx {
            match Pin::new(rx).poll(cx) {
                Poll::Ready(Ok(msg)) => {
                    self.conn_err_rx = None;
                    self.set_terminal_error(msg);
                    return Err(self.terminal_io_error());
                }
                Poll::Ready(Err(_)) => {
                    self.conn_err_rx = None;
                    self.set_terminal_error("MASQUE H2 connection task ended");
                    return Err(self.terminal_io_error());
                }
                Poll::Pending => {}
            }
        }

        if self.idle_timeout.as_mut().poll(cx).is_ready() {
            self.set_terminal_error("MASQUE H2 idle timeout");
            return Err(self.terminal_io_error());
        }

        Ok(())
    }

    fn fill_pending_wire(&mut self) {
        let now = Instant::now();
        let _ = prune_outbound_queue(&mut self.outbound_queue, now, usize::MAX);

        while self.pending_wire.len() < H2_COALESCE_LIMIT {
            let Some((_, pkt)) = self.outbound_queue.pop_front() else {
                break;
            };
            encode_outgoing_capsule(&pkt, &mut self.pending_wire);
        }
    }

    fn poll_flush_outbound(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.terminal_error.is_some() {
            return Poll::Ready(Err(self.terminal_io_error()));
        }

        loop {
            if self.pending_wire.is_empty() {
                self.fill_pending_wire();
                if self.pending_wire.is_empty() {
                    return Poll::Ready(Ok(()));
                }
            }

            let want = self.pending_wire.len().min(H2_COALESCE_LIMIT);
            if self.send_stream.capacity() < want {
                self.send_stream.reserve_capacity(want);
            }

            let avail = match self.send_stream.poll_capacity(cx) {
                Poll::Ready(Some(Ok(n))) => n,
                Poll::Ready(Some(Err(e))) => {
                    self.set_terminal_error(format!("MASQUE H2 send capacity error: {e}"));
                    return Poll::Ready(Err(self.terminal_io_error()));
                }
                Poll::Ready(None) => {
                    self.set_terminal_error("MASQUE H2 send stream closed");
                    return Poll::Ready(Err(self.terminal_io_error()));
                }
                Poll::Pending => return Poll::Pending,
            };

            if avail == 0 {
                return Poll::Pending;
            }

            if self.pending_wire.len() < avail && !self.outbound_queue.is_empty() {
                self.fill_pending_wire();
            }

            let n = avail.min(self.pending_wire.len());
            let chunk = self.pending_wire.split_to(n).freeze();
            if let Err(e) = self.send_stream.send_data(chunk, false) {
                self.set_terminal_error(format!("MASQUE H2 send_data error: {e}"));
                return Poll::Ready(Err(self.terminal_io_error()));
            }
            self.reset_idle_timeout();
        }
    }

    fn poll_recv_inbound(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.recv_stream.poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let len = chunk.len();
                    if len > 0 {
                        if let Err(e) = self.recv_stream.flow_control().release_capacity(len) {
                            self.set_terminal_error(format!(
                                "MASQUE H2 flow_control release error: {e}"
                            ));
                            return Poll::Ready(Err(self.terminal_io_error()));
                        }
                        self.recv_buf.extend_from_slice(&chunk);
                        if let Err(msg) =
                            drain_capsules(&mut self.recv_buf, &mut self.inbound_queue)
                        {
                            self.set_terminal_error(msg);
                            return Poll::Ready(Err(self.terminal_io_error()));
                        }
                        self.reset_idle_timeout();
                        if !self.inbound_queue.is_empty() {
                            return Poll::Ready(Ok(()));
                        }
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    self.set_terminal_error(format!("MASQUE H2 recv error: {e}"));
                    return Poll::Ready(Err(self.terminal_io_error()));
                }
                Poll::Ready(None) => {
                    self.set_terminal_error("MASQUE H2 response stream closed by peer");
                    return Poll::Ready(Err(self.terminal_io_error()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Stream for H2PacketStream {
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if let Some(pkt) = self.inbound_queue.pop_front() {
            return Poll::Ready(Some(Ok(pkt)));
        }

        if self.terminal_error.is_some() {
            if self.emitted_terminal_error {
                return Poll::Ready(None);
            }
            self.emitted_terminal_error = true;
            return Poll::Ready(Some(Err(self.terminal_io_error())));
        }

        if let Err(err) = self.poll_connection_health(cx) {
            self.emitted_terminal_error = true;
            return Poll::Ready(Some(Err(err)));
        }

        if let Poll::Ready(Err(err)) = self.poll_flush_outbound(cx) {
            self.emitted_terminal_error = true;
            return Poll::Ready(Some(Err(err)));
        }

        match self.poll_recv_inbound(cx) {
            Poll::Ready(Ok(())) => {
                self.inbound_queue.pop_front().map_or(Poll::Pending, |pkt| Poll::Ready(Some(Ok(pkt))))
            }
            Poll::Ready(Err(err)) => {
                self.emitted_terminal_error = true;
                Poll::Ready(Some(Err(err)))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<Bytes> for H2PacketStream {
    type Error = io::Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.state == PacketSessionState::Closed || self.terminal_error.is_some() {
            return Poll::Ready(Err(self.terminal_io_error()));
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Bytes) -> io::Result<()> {
        if self.state == PacketSessionState::Closed || self.terminal_error.is_some() {
            return Err(self.terminal_io_error());
        }

        let now = Instant::now();
        let _ = prune_outbound_queue(
            &mut self.outbound_queue,
            now,
            DEFAULT_OUTBOUND_QUEUE_CAPACITY.saturating_sub(1),
        );
        self.outbound_queue.push_back((now, item));
        Ok(())
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.terminal_error.is_some() {
            return Poll::Ready(Err(self.terminal_io_error()));
        }
        if let Err(err) = self.poll_connection_health(cx) {
            return Poll::Ready(Err(err));
        }
        self.poll_flush_outbound(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.as_mut().poll_flush(cx);
        self.close_now();
        Poll::Ready(Ok(()))
    }
}

async fn run_h2_connection<IO>(
    mut connection: H2Connection<IO, Bytes>,
    mut ping_pong: Option<PingPong>,
    ping_interval: Duration,
    err_tx: oneshot::Sender<String>,
) where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let mut ping_sleep = Box::pin(tokio::time::sleep(ping_interval));
    let mut waiting_pong = false;
    let mut pong_deadline = Box::pin(tokio::time::sleep(H2_PING_TIMEOUT));

    let reason = loop {
        tokio::select! {
            res = &mut connection => {
                break match res {
                    Ok(()) => "MASQUE H2 connection closed cleanly".to_string(),
                    Err(e) => format!("MASQUE H2 connection error: {e}"),
                };
            }
            () = &mut ping_sleep, if !waiting_pong && ping_pong.is_some() => {
                if let Some(pp) = &mut ping_pong {
                    if let Err(e) = pp.send_ping(Ping::opaque()) {
                        break format!("MASQUE H2 ping send error: {e}");
                    }
                    waiting_pong = true;
                    pong_deadline.as_mut().reset(Instant::now() + H2_PING_TIMEOUT);
                }
            }
            res = std::future::poll_fn(|cx| {
                ping_pong
                    .as_mut()
                    .map_or(Poll::Pending, |pp| pp.poll_pong(cx))
            }), if waiting_pong => {
                match res {
                    Ok(_) => {
                        waiting_pong = false;
                        ping_sleep.as_mut().reset(Instant::now() + ping_interval);
                    }
                    Err(e) => break format!("MASQUE H2 pong error: {e}"),
                }
            }
            () = &mut pong_deadline, if waiting_pong => {
                break format!("MASQUE H2 keepalive ping timed out after {H2_PING_TIMEOUT:?}");
            }
        }
    };

    let _ = err_tx.send(reason);
}

async fn connect_tcp(
    endpoint: SocketAddr,
    bind: Option<SocketAddr>,
    cc: CongestionControl,
) -> Result<TcpStream> {
    let socket = match endpoint {
        SocketAddr::V4(_) => TcpSocket::new_v4(),
        SocketAddr::V6(_) => TcpSocket::new_v6(),
    }
    .context("failed to create TCP socket for MASQUE H2")?;

    if let Some(bind_addr) = bind {
        socket
            .bind(bind_addr)
            .with_context(|| format!("failed to bind MASQUE H2 TCP socket to {bind_addr}"))?;
    }

    let stream = socket
        .connect(endpoint)
        .await
        .with_context(|| format!("failed to connect MASQUE H2 TCP socket to {endpoint}"))?;

    stream
        .set_nodelay(true)
        .context("failed to set TCP_NODELAY on MASQUE H2 socket")?;

    let keepalive = TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    if let Err(err) = SockRef::from(&stream).set_tcp_keepalive(&keepalive) {
        log::debug!("failed to set TCP keepalive on MASQUE H2 socket: {err}");
    }

    configure_linux_tcp_opts(&stream, cc);

    Ok(stream)
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn configure_linux_tcp_opts(stream: &TcpStream, cc: CongestionControl) {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    // Limit unsent kernel TCP queue so low-rate congestion pushes backpressure into
    // our age-bounded outbound_queue (100ms) instead of bloating latency to 3s+.
    // SAFETY: valid fd and properly sized c_int value for TCP_NOTSENT_LOWAT.
    let lowat = H2_TCP_NOTSENT_LOWAT;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NOTSENT_LOWAT,
            (&raw const lowat).cast::<libc::c_void>(),
            std::mem::size_of_val(&lowat) as libc::socklen_t,
        )
    };
    if rc != 0 {
        log::debug!("TCP_NOTSENT_LOWAT setsockopt failed: {}", io::Error::last_os_error());
    }

    if cc == CongestionControl::Bbr2 {
        let alg = b"bbr";
        // SAFETY: valid fd and byte slice length for TCP_CONGESTION.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_CONGESTION,
                alg.as_ptr().cast::<libc::c_void>(),
                alg.len() as libc::socklen_t,
            )
        };
        if rc != 0 {
            log::debug!("TCP_CONGESTION=bbr unavailable on host kernel: {}", io::Error::last_os_error());
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn configure_linux_tcp_opts(_stream: &TcpStream, _cc: CongestionControl) {}

fn build_connect_ip_request() -> Result<Request<()>> {
    let uri = Uri::builder()
        .authority(H2_CONNECT_AUTHORITY)
        .build()
        .context("failed to build H2 CONNECT authority URI")?;

    let mut req = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .body(())
        .context("failed to build H2 CONNECT-IP request")?;

    let headers = req.headers_mut();
    headers.insert("cf-connect-proto", HeaderValue::from_static("cf-connect-ip"));
    headers.insert("pq-enabled", HeaderValue::from_static("false"));
    headers.insert("user-agent", HeaderValue::from_static(""));
    Ok(req)
}

#[derive(Debug)]
struct PinnedEndpointVerifier {
    expected_spki_der: Vec<u8>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinnedEndpointVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        if tls::verify_endpoint_key(end_entity.as_ref(), &self.expected_spki_der) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(TlsError::InvalidCertificate(CertificateError::UnknownIssuer))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

fn build_rustls_client_config(tls_der: &TlsDerMaterial) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(PinnedEndpointVerifier {
        expected_spki_der: tls_der.endpoint_pub_key_spki_der.clone(),
        supported_algs: provider.signature_verification_algorithms,
    });

    let cert_chain = vec![CertificateDer::from(tls_der.cert_der.clone())];
    let priv_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(tls_der.key_pkcs8_der.clone()));

    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("failed to configure rustls TLS versions")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(cert_chain, priv_key)
        .context("failed to configure rustls client certificate")?;

    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Ok(Arc::new(cfg))
}

pub(crate) fn encode_outgoing_capsule(raw_ip_packet: &[u8], dst: &mut BytesMut) -> bool {
    let mut prepared = raw_ip_packet.to_vec();
    if packet::prepare_outgoing(&mut prepared).is_err() {
        log::trace!("dropping invalid outgoing IP packet before MASQUE H2 send");
        return false;
    }
    append_capsule(H2_DATAGRAM_CAPSULE_TYPE, &prepared, dst);
    true
}

fn append_capsule(capsule_type: u64, payload: &[u8], dst: &mut BytesMut) {
    let mut hdr = [0u8; 16];
    let mut builder = OctetsMut::with_slice(&mut hdr);
    builder.put_varint(capsule_type).unwrap();
    builder.put_varint(payload.len() as u64).unwrap();
    let hdr_len = builder.off();
    dst.reserve(hdr_len + payload.len());
    dst.put_slice(&hdr[..hdr_len]);
    dst.put_slice(payload);
}

fn parse_varint(buf: &[u8]) -> Option<(u64, usize)> {
    let first = *buf.first()?;
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return None;
    }
    let mut val = u64::from(first & 0x3f);
    for &b in &buf[1..len] {
        val = (val << 8) | u64::from(b);
    }
    Some((val, len))
}

pub(crate) fn drain_capsules(
    recv_buf: &mut BytesMut,
    inbound_queue: &mut VecDeque<Bytes>,
) -> std::result::Result<usize, String> {
    let mut decoded = 0;
    while let Some((capsule_type, type_len)) = parse_varint(recv_buf) {
        let Some((payload_len_u64, len_len)) = parse_varint(&recv_buf[type_len..]) else {
            break;
        };
        let Ok(payload_len) = usize::try_from(payload_len_u64) else {
            return Err("MASQUE H2 capsule length overflow".to_string());
        };
        if payload_len > MAX_CAPSULE_PAYLOAD_LEN {
            return Err(format!(
                "MASQUE H2 capsule length {payload_len} exceeds limit {MAX_CAPSULE_PAYLOAD_LEN}"
            ));
        }

        let header_len = type_len + len_len;
        let Some(total_len) = header_len.checked_add(payload_len) else {
            return Err("MASQUE H2 capsule total length overflow".to_string());
        };
        if recv_buf.len() < total_len {
            break;
        }

        let mut frame = recv_buf.split_to(total_len);
        if capsule_type == H2_DATAGRAM_CAPSULE_TYPE && payload_len > 0 {
            let payload = frame.split_off(header_len).freeze();
            if inbound_queue.len() < DEFAULT_INBOUND_QUEUE_CAPACITY {
                inbound_queue.push_back(payload);
                decoded += 1;
            }
        }
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt, StreamExt};

    fn sample_ipv4_packet(ttl: u8) -> Bytes {
        let mut pkt = vec![
            0x45, 0x00, 0x00, 0x18, 0x00, 0x01, 0x00, 0x00, ttl, 0x11, 0x00, 0x00, 10, 0, 0, 1, 10,
            0, 0, 2, b't', b'e', b's', b't',
        ];
        let mut sum: u32 = 0;
        for chunk in pkt[..20].chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        let csum = !(sum as u16);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        Bytes::from(pkt)
    }

    #[test]
    fn capsule_roundtrip_handles_fragmentation_and_unknown_types() {
        let mut wire = BytesMut::new();
        append_capsule(0x15, b"ignore-me", &mut wire);
        let ip1 = sample_ipv4_packet(64);
        assert!(encode_outgoing_capsule(&ip1, &mut wire));
        let large = vec![0x60; 200];
        append_capsule(H2_DATAGRAM_CAPSULE_TYPE, &large, &mut wire);

        let mut recv_buf = BytesMut::new();
        let mut inbound = VecDeque::new();
        for &b in &wire {
            recv_buf.put_u8(b);
            drain_capsules(&mut recv_buf, &mut inbound).unwrap();
        }

        assert!(recv_buf.is_empty());
        assert_eq!(inbound.len(), 2);
        assert_eq!(inbound[0][8], 63);
        assert_eq!(inbound[1].as_ref(), large.as_slice());
    }

    #[test]
    fn capsule_rejects_oversized_frame() {
        let mut recv_buf = BytesMut::new();
        let mut hdr = [0u8; 16];
        let mut builder = OctetsMut::with_slice(&mut hdr);
        builder.put_varint(0).unwrap();
        builder
            .put_varint((MAX_CAPSULE_PAYLOAD_LEN + 1) as u64)
            .unwrap();
        let n = builder.off();
        recv_buf.put_slice(&hdr[..n]);

        let mut inbound = VecDeque::new();
        assert!(drain_capsules(&mut recv_buf, &mut inbound).is_err());
    }

    #[tokio::test]
    async fn h2_packet_stream_connect_and_exchange_capsules_in_memory() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server_io).await.unwrap();
            let (req, mut respond) = conn.accept().await.unwrap().unwrap();
            assert_eq!(req.method(), Method::CONNECT);
            assert_eq!(
                req.uri().authority().map(http::uri::Authority::as_str),
                Some(H2_CONNECT_AUTHORITY)
            );
            assert_eq!(
                req.headers()
                    .get("cf-connect-proto")
                    .and_then(|v| v.to_str().ok()),
                Some("cf-connect-ip")
            );
            assert_eq!(
                req.headers()
                    .get("pq-enabled")
                    .and_then(|v| v.to_str().ok()),
                Some("false")
            );

            let resp = http::Response::builder().status(200).body(()).unwrap();
            let mut server_send = respond.send_response(resp, false).unwrap();
            let mut server_recv = req.into_body();

            let mut rx_buf = BytesMut::new();
            let mut echo_q = VecDeque::new();
            loop {
                tokio::select! {
                    _ = std::future::poll_fn(|cx| conn.poll_accept(cx)) => {}
                    chunk = server_recv.data() => {
                        let Some(Ok(data)) = chunk else { break };
                        let _ = server_recv.flow_control().release_capacity(data.len());
                        rx_buf.extend_from_slice(&data);
                        drain_capsules(&mut rx_buf, &mut echo_q).unwrap();
                        if let Some(pkt) = echo_q.pop_front() {
                            let mut out = BytesMut::new();
                            append_capsule(H2_DATAGRAM_CAPSULE_TYPE, &pkt, &mut out);
                            server_send.send_data(out.freeze(), false).unwrap();
                            break;
                        }
                    }
                }
            }
            let _ = tokio::time::timeout(Duration::from_millis(200), async {
                while conn.accept().await.is_some() {}
            })
            .await;
        });

        let mut stream = H2PacketStream::handshake_over_io(client_io, Duration::from_secs(30))
            .await
            .unwrap();
        assert_eq!(stream.state(), PacketSessionState::Ready);

        let pkt = sample_ipv4_packet(64);
        stream.send(pkt.clone()).await.unwrap();

        let echoed = tokio::time::timeout(Duration::from_secs(2), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(echoed.len(), pkt.len());
        assert_eq!(echoed[8], 63);

        stream.close_now();
        let _ = server_task.await;
    }
}

