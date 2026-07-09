//! meshguard command-line client/server.
//!
//! Usage:
//!   meshguard id                       Print this node's NodeId + derived identity.
//!   meshguard selftest                 In-process handshake + data round-trip         (no root/net).
//!   meshguard connect <NodeId> [opts]  Bring up a VPN to a peer by NodeId.            (features: full)
//!   meshguard serve [opts]             Accept tunnels from peers.                     (features: full)
//!
//! Options: --iface <name> (default meshguard0), --mtu <n> (default 1280)

use meshguard::config::load_or_create_identity;

fn usage() -> ! {
    eprintln!(
        "meshguard {}\n\
         \nUSAGE:\n  \
         meshguard id\n  \
         meshguard selftest\n  \
         meshguard connect <NodeId> [--iface <name>] [--mtu <n>]\n  \
         meshguard serve [--iface <name>] [--mtu <n>]\n",
        env!("CARGO_PKG_VERSION")
    );
    std::process::exit(2);
}

struct Opts {
    iface: String,
    mtu: u16,
}

fn parse_opts(args: &[String]) -> Opts {
    let mut iface = "meshguard0".to_string();
    let mut mtu: u16 = 1280;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--iface" => {
                i += 1;
                iface = args.get(i).cloned().unwrap_or_else(|| usage());
            }
            "--mtu" => {
                i += 1;
                mtu = args
                    .get(i)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(|| usage());
            }
            _ => usage(),
        }
        i += 1;
    }
    Opts { iface, mtu }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("");
    match cmd {
        "id" => {
            let id = load_or_create_identity()?;
            println!("NodeId     : {}", id.node_id_string());
            println!(
                "WG public  : {}",
                data_encoding::BASE64.encode(id.wg_public().as_bytes())
            );
            println!("Overlay IP : {}", id.overlay_ip());
            println!(
                "\nShare your NodeId. A peer connects with:\n  meshguard connect {}",
                id.node_id_string()
            );
        }
        "selftest" => {
            println!("Running in-process WireGuard handshake over an in-memory transport...");
            let n = meshguard::selftest().await?;
            println!(
                "OK: {n} plaintext bytes traversed the tunnel (encrypt -> handshake -> decrypt)."
            );
        }
        "connect" => {
            let node_id = args.get(1).cloned().unwrap_or_else(|| usage());
            let opts = parse_opts(&args[2..]);
            connect(node_id, opts.iface, opts.mtu).await?;
        }
        "serve" => {
            let opts = parse_opts(&args[1..]);
            serve(opts.iface, opts.mtu).await?;
        }
        _ => usage(),
    }
    Ok(())
}

#[cfg(all(feature = "iroh", feature = "tun"))]
async fn connect(node_id: String, iface: String, mtu: u16) -> anyhow::Result<()> {
    use meshguard::io::Transport;
    use meshguard::transport::iroh::{make_endpoint, parse_node_id, IrohTransport};
    use std::sync::{Arc, Mutex};

    let id = load_or_create_identity()?;
    println!("This node: {}", id.node_id_string());

    let peer = parse_node_id(&node_id)?;
    let peer_key = meshguard::identity::parse_node_key(&node_id)?;

    let ep = make_endpoint(&id).await?;
    println!("Dialing {node_id} over iroh...");
    let transport = IrohTransport::dial(&ep, peer).await?;
    println!("Connected. Bringing up {iface} ({}).", id.overlay_ip());

    let io = meshguard::tun::setup(&iface, id.overlay_ip(), mtu).await?;
    let tunn = Arc::new(Mutex::new(meshguard::tunnel::build_tunn(
        &id, &peer_key, Some(25),
    )?));

    meshguard::tunnel::run(
        tunn,
        Arc::new(transport) as Arc<dyn Transport>,
        Arc::new(io),
        true, // client initiates the handshake
    )
    .await
}

#[cfg(all(feature = "iroh", feature = "tun"))]
async fn serve(iface: String, mtu: u16) -> anyhow::Result<()> {
    use meshguard::io::Transport;
    use meshguard::transport::iroh::{make_endpoint, IrohTransport};
    use std::sync::{Arc, Mutex};

    let id = load_or_create_identity()?;
    let ep = make_endpoint(&id).await?;
    println!("Serving as {}", id.node_id_string());
    println!("Peers connect with:  meshguard connect {}", id.node_id_string());

    let io: Arc<dyn meshguard::io::PacketIo> =
        Arc::new(meshguard::tun::setup(&iface, id.overlay_ip(), mtu).await?);

    while let Some(incoming) = ep.accept().await {
        let conn = match incoming.await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("incoming connection failed: {e}");
                continue;
            }
        };
        let transport = IrohTransport::from_connection(conn);
        let peer = transport.remote_node_id()?;
        let peer_key = *peer.as_bytes();
        println!("Peer connected: {peer}");

        // Membership hook: decide whether this NodeId is allowed. (Prototype: allow all.)
        let tunn = Arc::new(Mutex::new(meshguard::tunnel::build_tunn(
            &id, &peer_key, Some(25),
        )?));
        let io2 = io.clone();
        tokio::spawn(async move {
            let _ = meshguard::tunnel::run(
                tunn,
                Arc::new(transport) as Arc<dyn Transport>,
                io2,
                false, // server responds to the handshake
            )
            .await;
        });
    }
    Ok(())
}

#[cfg(not(all(feature = "iroh", feature = "tun")))]
async fn connect(_node_id: String, _iface: String, _mtu: u16) -> anyhow::Result<()> {
    anyhow::bail!(
        "Built without the iroh transport and/or TUN support.\n\
         Rebuild with:  cargo build --release --features full\n"
    )
}

#[cfg(not(all(feature = "iroh", feature = "tun")))]
async fn serve(_iface: String, _mtu: u16) -> anyhow::Result<()> {
    anyhow::bail!(
        "Built without the iroh transport and/or TUN support.\n\
         Rebuild with:  cargo build --release --features full\n"
    )
}
