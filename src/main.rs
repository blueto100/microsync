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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatMessage {
    pub sender: String,
    pub text: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct AppState {
    pub history: Vec<ChatMessage>,
}

struct ConnectionSettings {
    username: String,
    room_name: String,
    password: String,
    local_port: u16,
    peer_ip: String,
    peer_port: u16,
    is_connected: bool,
    packets_sent: u64,
    packets_received: u64,
    last_peer_seen: String,
}

impl Default for ConnectionSettings {
    fn default() -> Self {
        Self {
            username: "User".to_string(),
            room_name: "default_room".to_string(),
            password: "".to_string(),
            local_port: 5555,
            peer_ip: "127.0.0.1".to_string(),
            peer_port: 5555,
            is_connected: false,
            packets_sent: 0,
            packets_received: 0,
            last_peer_seen: "None".to_string(),
        }
    }
}

struct MicroSyncApp {
    state: Arc<Mutex<AppState>>,
    settings: Arc<Mutex<ConnectionSettings>>,
    current_input: String,
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
        Self { state, settings, current_input: String::new(), tx, connect_tx }
    }

    fn derive_key(room: &str, password: &str) -> [u8; 32] {
        use argon2::password_hash::{SaltString, PasswordHasher};
        let mut salt_bytes = [0u8; 16];
        let room_bytes = room.as_bytes();
        for i in 0..16 {
            if i < room_bytes.len() { salt_bytes[i] = room_bytes[i]; }
            else { salt_bytes[i] = b'0' + (i as u8); }
        }
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

        egui::TopBottomPanel::top("settings").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("🔒 Secure Chat");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button(if settings.is_connected { "Reconnect" } else { "Connect" }).clicked() {
                        let _ = self.connect_tx.send(());
                    }
                });
            });

            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut settings.username).hint_text("Name").desired_width(60.0));
                ui.add(egui::TextEdit::singleline(&mut settings.room_name).hint_text("Room").desired_width(80.0));
                ui.add(egui::TextEdit::singleline(&mut settings.password).password(true).hint_text("Pass").desired_width(80.0));
                ui.label("Port:");
                ui.add(egui::DragValue::new(&mut settings.local_port));
            });

            ui.horizontal(|ui| {
                ui.label("Friend IP:");
                ui.add(egui::TextEdit::singleline(&mut settings.peer_ip).desired_width(120.0));
                ui.label("Port:");
                ui.add(egui::DragValue::new(&mut settings.peer_port));
            });
            
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(format!("📤 Sent: {}", settings.packets_sent)).size(10.0).color(egui::Color32::LIGHT_BLUE));
                ui.label(egui::RichText::new(format!("📥 Received: {}", settings.packets_received)).size(10.0).color(egui::Color32::LIGHT_GREEN));
                ui.label(egui::RichText::new(format!("📍 Last From: {}", settings.last_peer_seen)).size(10.0).color(egui::Color32::GRAY));
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if !settings.is_connected {
                ui.centered_and_justified(|ui| {
                    ui.label("Enter settings and click Connect");
                });
            } else {
                egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                    for msg in &state.history {
                        ui.horizontal(|ui| {
                            ui.label(egui::RichText::new(format!("{}: ", msg.sender)).strong());
                            ui.label(&msg.text);
                        });
                    }
                });
            }
        });

        if settings.is_connected {
            egui::TopBottomPanel::bottom("input").show(ctx, |ui| {
                ui.add_space(5.0);
                ui.horizontal(|ui| {
                    let response = ui.add_sized(
                        [ui.available_width() - 60.0, 30.0],
                        egui::TextEdit::singleline(&mut self.current_input).hint_text("Type a message...")
                    );
                    
                    if (ui.button("Send").clicked() || (response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))) && !self.current_input.is_empty() {
                        state.history.push(ChatMessage {
                            sender: settings.username.clone(),
                            text: self.current_input.clone(),
                        });
                        let _ = self.tx.send(state.clone());
                        self.current_input.clear();
                        response.request_focus();
                    }
                });
                ui.add_space(5.0);
            });
        }

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

    let net_state = state.clone();
    let net_settings = settings.clone();
    tokio::spawn(async move {
        let mut socket: Option<Arc<UdpSocket>> = None;
        let mut key: Option<[u8; 32]> = None;

        loop {
            tokio::select! {
                _ = connect_rx.recv() => {
                    let (bind_addr, k_params) = {
                        let s = net_settings.lock().unwrap();
                        (format!("0.0.0.0:{}", s.local_port), (s.room_name.clone(), s.password.clone()))
                    };
                    
                    match UdpSocket::bind(&bind_addr).await {
                        Ok(sock) => {
                            println!("✅ Bound to {}", bind_addr);
                            socket = Some(Arc::new(sock));
                            key = Some(MicroSyncApp::derive_key(&k_params.0, &k_params.1));
                            net_settings.lock().unwrap().is_connected = true;
                        }
                        Err(e) => println!("❌ Bind error: {}", e),
                    }
                }

                Some(new_state) = rx.recv() => {
                    if let (Some(sock), Some(k)) = (&socket, &key) {
                        let target = {
                            let s = net_settings.lock().unwrap();
                            format!("{}:{}", s.peer_ip, s.peer_port)
                        };

                        if let Ok(data) = bincode::serialize(&new_state) {
                            let cipher = ChaCha20Poly1305::new(k.into());
                            let mut nonce_bytes = [0u8; 12];
                            rand::thread_rng().fill_bytes(&mut nonce_bytes);
                            let nonce = Nonce::from_slice(&nonce_bytes);

                            if let Ok(ciphertext) = cipher.encrypt(nonce, data.as_ref()) {
                                let mut packet = nonce_bytes.to_vec();
                                packet.extend_from_slice(&ciphertext);
                                if let Ok(_) = sock.send_to(&packet, &target).await {
                                    net_settings.lock().unwrap().packets_sent += 1;
                                }
                            }
                        }
                    }
                }

                res = async {
                    if let Some(sock) = &socket {
                        let mut buf = [0u8; 8192];
                        match sock.recv_from(&mut buf).await {
                            Ok((len, addr)) => Some((buf[..len].to_vec(), addr)),
                            Err(_) => None,
                        }
                    } else {
                        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                        None
                    }
                } => {
                    if let (Some((packet, addr)), Some(k)) = (res, &key) {
                        let mut s_lock = net_settings.lock().unwrap();
                        s_lock.packets_received += 1;
                        s_lock.last_peer_seen = addr.to_string();
                        drop(s_lock);

                        if packet.len() > 12 {
                            let nonce = Nonce::from_slice(&packet[..12]);
                            let ciphertext = &packet[12..];
                            let cipher = ChaCha20Poly1305::new(k.into());

                            if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext) {
                                if let Ok(new_state) = bincode::deserialize::<AppState>(&plaintext) {
                                    let mut s = net_state.lock().unwrap();
                                    *s = new_state;
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([500.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "MicroSync Diagnostics",
        options,
        Box::new(|cc| Box::new(MicroSyncApp::new(cc, state, settings, tx, connect_tx))),
    )
}
