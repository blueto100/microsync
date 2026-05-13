#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::net::UdpSocket;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use argon2::{
    Argon2,
};
use rand::RngCore;

const DEFAULT_PORT: u16 = 5555;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AppState {
    pub message: String,
    pub counter: u32,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            message: "Hello Secure MicroSync!".to_string(),
            counter: 0,
        }
    }
}

struct ConnectionSettings {
    room_name: String,
    password: String,
    peer_ip: String,
    is_connected: bool,
}

impl Default for ConnectionSettings {
    fn default() -> Self {
        Self {
            room_name: "default_room".to_string(),
            password: "".to_string(),
            peer_ip: "127.0.0.1".to_string(),
            is_connected: false,
        }
    }
}

struct MicroSyncApp {
    state: Arc<Mutex<AppState>>,
    settings: Arc<Mutex<ConnectionSettings>>,
    tx: mpsc::UnboundedSender<AppState>,
    connect_tx: mpsc::UnboundedSender<()>,
}

impl MicroSyncApp {
    fn new(
        _cc: &eframe::CreationContext<'_>,
        state: Arc<Mutex<AppState>>,
        settings: Arc<Mutex<ConnectionSettings>>,
        tx: mpsc::UnboundedSender<AppState>,
        connect_tx: mpsc::UnboundedSender<()>,
    ) -> Self {
        Self { state, settings, tx, connect_tx }
    }

    fn derive_key(room: &str, password: &str) -> [u8; 32] {
        use argon2::password_hash::{SaltString, PasswordHasher};
        
        // Create a 16-byte buffer from the room name (padded/truncated)
        let mut salt_bytes = [0u8; 16];
        let room_bytes = room.as_bytes();
        for i in 0..16 {
            if i < room_bytes.len() {
                salt_bytes[i] = room_bytes[i];
            } else {
                salt_bytes[i] = b'0' + (i as u8);
            }
        }

        // Encode to Base64 to make it a valid SaltString
        let salt_str = SaltString::encode_b64(&salt_bytes).unwrap();
        let argon2 = Argon2::default();
        
        if let Ok(hash) = argon2.hash_password(password.as_bytes(), &salt_str) {
            if let Some(output) = hash.hash {
                let mut key = [0u8; 32];
                let bytes = output.as_bytes();
                let len = bytes.len().min(32);
                key[..len].copy_from_slice(&bytes[..len]);
                return key;
            }
        }
        
        [0u8; 32]
    }
}

impl eframe::App for MicroSyncApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let mut state = self.state.lock().unwrap();
        let mut settings = self.settings.lock().unwrap();

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🔒 MicroSync Secure P2P");
            
            ui.group(|ui| {
                ui.label("Connection Settings");
                ui.add(egui::TextEdit::singleline(&mut settings.room_name).hint_text("Room Name"));
                ui.add(egui::TextEdit::singleline(&mut settings.password).password(true).hint_text("Password"));
                ui.add(egui::TextEdit::singleline(&mut settings.peer_ip).hint_text("Friend's IP"));
                
                if ui.button(if settings.is_connected { "Reconnect" } else { "Connect" }).clicked() {
                    let _ = self.connect_tx.send(());
                }
            });

            ui.add_space(10.0);
            
            if settings.is_connected {
                ui.label(format!("Status: Encrypted Room [{}]", settings.room_name));
                
                ui.separator();

                ui.horizontal(|ui| {
                    ui.label("Message:");
                    if ui.text_edit_singleline(&mut state.message).changed() {
                        let _ = self.tx.send(state.clone());
                    }
                });

                ui.horizontal(|ui| {
                    ui.label(format!("Counter: {}", state.counter));
                    if ui.button("Increment").clicked() {
                        state.counter += 1;
                        let _ = self.tx.send(state.clone());
                    }
                });
            } else {
                ui.label("Status: Offline. Enter settings and click Connect.");
            }
        });

        // Repaint periodically to check for background updates
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}

#[tokio::main]
async fn main() -> Result<(), eframe::Error> {
    env_logger::init();

    let state = Arc::new(Mutex::new(AppState::default()));
    let settings = Arc::new(Mutex::new(ConnectionSettings::default()));
    
    let (tx, mut rx) = mpsc::unbounded_channel::<AppState>();
    let (connect_tx, mut connect_rx) = mpsc::unbounded_channel::<()>();

    // Networking Task
    let net_state = state.clone();
    let net_settings = settings.clone();
    tokio::spawn(async move {
        let mut socket: Option<Arc<UdpSocket>> = None;
        let mut key: Option<[u8; 32]> = None;

        loop {
            tokio::select! {
                // Handle new connection requests
                _ = connect_rx.recv() => {
                    let bind_addr = {
                        let _s = net_settings.lock().unwrap();
                        format!("0.0.0.0:{}", DEFAULT_PORT)
                    };
                    
                    match UdpSocket::bind(&bind_addr).await {
                        Ok(sock) => {
                            println!("Bound to {}", bind_addr);
                            socket = Some(Arc::new(sock));
                            let s = net_settings.lock().unwrap();
                            key = Some(MicroSyncApp::derive_key(&s.room_name, &s.password));
                            drop(s);
                            net_settings.lock().unwrap().is_connected = true;
                        }
                        Err(e) => println!("Failed to bind: {}", e),
                    }
                }

                // Handle local state changes (Send to peer)
                Some(new_state) = rx.recv() => {
                    if let (Some(sock), Some(k)) = (&socket, &key) {
                        let target = {
                            let s = net_settings.lock().unwrap();
                            format!("{}:{}", s.peer_ip, DEFAULT_PORT)
                        };

                        if let Ok(data) = bincode::serialize(&new_state) {
                            let cipher = ChaCha20Poly1305::new(k.into());
                            let mut nonce_bytes = [0u8; 12];
                            rand::thread_rng().fill_bytes(&mut nonce_bytes);
                            let nonce = Nonce::from_slice(&nonce_bytes);

                            if let Ok(ciphertext) = cipher.encrypt(nonce, data.as_ref()) {
                                // Packet: Nonce + Ciphertext
                                let mut packet = nonce_bytes.to_vec();
                                packet.extend_from_slice(&ciphertext);
                                let _ = sock.send_to(&packet, &target).await;
                                println!("Sent encrypted state to {}", target);
                            }
                        }
                    }
                }

                // Handle incoming packets (Receive from peer)
                // We use a temporary buffer for UDP
                res = async {
                    if let Some(sock) = &socket {
                        let mut buf = [0u8; 1024];
                        match sock.recv_from(&mut buf).await {
                            Ok((len, _addr)) => Some(buf[..len].to_vec()),
                            Err(_) => None,
                        }
                    } else {
                        // Sleep a bit if no socket to avoid busy loop
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        None
                    }
                } => {
                    if let (Some(packet), Some(k)) = (res, &key) {
                        if packet.len() > 12 {
                            let nonce = Nonce::from_slice(&packet[..12]);
                            let ciphertext = &packet[12..];
                            let cipher = ChaCha20Poly1305::new(k.into());

                            if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext) {
                                if let Ok(new_state) = bincode::deserialize::<AppState>(&plaintext) {
                                    let mut s = net_state.lock().unwrap();
                                    *s = new_state;
                                    println!("Received and decrypted state update");
                                }
                            } else {
                                println!("Failed to decrypt packet (Wrong password or room?)");
                            }
                        }
                    }
                }
            }
        }
    });

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([400.0, 450.0]),
        ..Default::default()
    };

    eframe::run_native(
        "MicroSync Secure",
        options,
        Box::new(|cc| Box::new(MicroSyncApp::new(cc, state, settings, tx, connect_tx))),
    )
}
