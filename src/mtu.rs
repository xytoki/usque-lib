//! MTU-derived outer QUIC packet sizing.
//!
//! The configured tunnel MTU is the advertised inner IP packet size. The
//! outer QUIC/UDP payload must be large enough to carry one full-size
//! inner packet plus encapsulation overhead, so that CONNECT-IP datagrams
//! (which cannot be fragmented) always fit into exactly one outer packet.

/// Extra bytes beyond the tunnel MTU needed for one outer QUIC packet.
///
/// QUIC short header (1 + DCID + PN) + AEAD tag (16) + DATAGRAM frame
/// type (1) + capsule context varint. Measured 43-44 in practice; kept
/// slightly larger for CID/PN/varint growth.
pub const OUTER_MARGIN: usize = 48;

/// Largest outer QUIC/UDP payload a session may send or receive, derived
/// from the advertised tunnel MTU. Clamped to the range QUIC allows for
/// the [`max_udp_payload_size`] transport parameter.
pub fn max_datagram_size(mtu: u32) -> usize {
    (mtu as usize + OUTER_MARGIN).clamp(1200, 65_527)
}
