//! End-to-end test of the WireGuard engine over an in-memory transport:
//! two independent identities complete a Noise_IKpsk2 handshake and exchange an
//! encrypted IP packet, with peer keys derived purely from NodeIds.

#[tokio::test]
async fn packet_traverses_the_tunnel() {
    let bytes = meshguard::selftest()
        .await
        .expect("selftest should complete");
    assert!(bytes >= 20, "expected a full IP packet, got {bytes} bytes");
}
