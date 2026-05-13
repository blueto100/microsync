#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::net::UdpSocket;
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
use argon2::Argon2;
use rand::RngCore;
use std::collections::HashMap;
use std::fs;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Friend {
    pub name: String,
    pub ip: String,
    pub port: u16,
    #[serde(skip)]
    pub is_online: bool,
    #[serde(skip)]
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum PacketType {
    Chat(String),
    Ping,
    Pong,
    VideoSignal(String),
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecurePacket {
    pub sender: String,
    pub p_type: PacketType,
}

struct FriendsStore {
    path: String,
}

impl FriendsStore {
    fn load(&self) -> HashMap<String, Friend> {
        if let Ok(content) = fs::read_to_string(&self.path) {
            toml::from_str(&content).unwrap_or_default()
        } else {
            HashMap::new()
        }
    }
    fn save(&self, friends: &HashMap<String, Friend>) {
        if let Ok(content) = toml::to_string(friends) {
            let _ = fs::write(&self.path, content);
        }
    }
}

struct ConnectionSettings {
    username: String,
    room_name: String,
    password: String,
    local_port: u16,
    is_connected: bool,
    friends: HashMap<String, Friend>,
}

impl Default for ConnectionSettings {
    fn default() -> Self {
        Self {
            username: "User".to_string(),
            room_name: "default_room".to_string(),
            password: "".to_string(),
            local_port: 5555,
            is_connected: false,
            friends: HashMap::new(),
        }
    }
}

struct MicroSyncApp {
    settings: Arc<Mutex<ConnectionSettings>>,
    chat_history: Arc<Mutex<Vec<(String, String)>>>,
    current_input: String,
    new_friend_name: String,
    new_friend_ip: String,
    new_friend_port: String,
    tx: mpsc::UnboundedSender<SecurePacket>,
    connect_tx: mpsc::UnboundedSender<()>,
    store: FriendsStore,
}

impl MicroSyncApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let store = FriendsStore { path: "friends.toml".to_string() };
        let mut initial_settings = ConnectionSettings::default();
        initial_settings.friends = store.load();

        let (tx, rx_net) = mpsc::unbounded_channel::<SecurePacket>();
        let (connect_tx, connect_rx) = mpsc::unbounded_channel::<()>();
        let settings = Arc::new(Mutex::new(initial_settings));
        let chat_history = Arc::new(Mutex::new(Vec::new()));

        start_networking(settings.clone(), chat_history.clone(), rx_net, connect_rx);

        Self {
            settings,
            chat_history,
            current_input: String::new(),
            new_friend_name: String::new(),
            new_friend_ip: String::new(),
            new_friend_port: "5555".to_string(),
            tx,
            connect_tx,
            store,
        }
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
        let mut settings = self.settings.lock().unwrap();
        let chat = self.chat_history.lock().unwrap();

        egui::SidePanel::left("friends_list").show(ctx, |ui| {
            ui.heading("👥 Friends");
            ui.separator();
            
            for (name, friend) in &settings.friends {
                ui.horizontal(|ui| {
                    let color = if friend.is_online { egui::Color32::GREEN } else { egui::Color32::GRAY };
                    ui.colored_label(color, "●");
                    ui.label(name);
                    ui.label(format!("({}:{})", friend.ip, friend.port));
                });
            }

            ui.add_space(20.0);
            ui.label("Add Friend:");
            ui.add(egui::TextEdit::singleline(&mut self.new_friend_name).hint_text("Name"));
            ui.add(egui::TextEdit::singleline(&mut self.new_friend_ip).hint_text("IP Address"));
            ui.add(egui::TextEdit::singleline(&mut self.new_friend_port).hint_text("Port"));
            
            if ui.button("Add Friend").clicked() && !self.new_friend_name.is_empty() {
                let port = self.new_friend_port.parse::<u16>().unwrap_or(5555);
                settings.friends.insert(self.new_friend_name.clone(), Friend {
                    name: self.new_friend_name.clone(),
                    ip: self.new_friend_ip.clone(),
                    port,
                    is_online: false,
                    last_seen: None,
                });
                self.store.save(&settings.friends);
                self.new_friend_name.clear();
                self.new_friend_ip.clear();
                self.new_friend_port = "5555".to_string();
            }
        });

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("🔒 MicroSync P2P");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button(if settings.is_connected { "Connected" } else { "Connect" }).clicked() {
                        let _ = self.connect_tx.send(());
                    }
                });
            });
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut settings.username).hint_text("Name").desired_width(100.0));
                ui.add(egui::TextEdit::singleline(&mut settings.room_name).hint_text("Room").desired_width(100.0));
                ui.add(egui::TextEdit::singleline(&mut settings.password).password(true).hint_text("Pass").desired_width(100.0));
                ui.label("Local Port:");
                ui.add(egui::DragValue::new(&mut settings.local_port));
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical().stick_to_bottom(true).show(ui, |ui| {
                for (sender, text) in chat.iter() {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(format!("{}: ", sender)).strong());
                        ui.label(text);
                    });
                }
            });
        });

        egui::TopBottomPanel::bottom("input").show(ctx, |ui| {
            ui.add_space(5.0);
            ui.horizontal(|ui| {
                let response = ui.add_sized([ui.available_width() - 60.0, 30.0], egui::TextEdit::singleline(&mut self.current_input).hint_text("Type a message..."));
                if (ui.button("Send").clicked() || (response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))) && !self.current_input.is_empty() {
                    let _ = self.tx.send(SecurePacket {
                        sender: settings.username.clone(),
                        p_type: PacketType::Chat(self.current_input.clone()),
                    });
                    self.current_input.clear();
                    response.request_focus();
                }
            });
            ui.add_space(5.0);
        });

        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}

fn start_networking(
    settings: Arc<Mutex<ConnectionSettings>>,
    chat: Arc<Mutex<Vec<(String, String)>>>,
    mut rx_out: mpsc::UnboundedReceiver<SecurePacket>,
    mut rx_conn: mpsc::UnboundedReceiver<()>,
) {
    tokio::spawn(async move {
        let mut socket: Option<Arc<UdpSocket>> = None;
        let mut key: Option<[u8; 32]> = None;

        loop {
            tokio::select! {
                _ = rx_conn.recv() => {
                    let (addr, k_params) = {
                        let s = settings.lock().unwrap();
                        (format!("0.0.0.0:{}", s.local_port), (s.room_name.clone(), s.password.clone()))
                    };
                    if let Ok(sock) = UdpSocket::bind(&addr).await {
                        socket = Some(Arc::new(sock));
                        key = Some(MicroSyncApp::derive_key(&k_params.0, &k_params.1));
                        settings.lock().unwrap().is_connected = true;
                    }
                }

                Some(packet) = rx_out.recv() => {
                    if let (Some(sock), Some(k)) = (&socket, &key) {
                        let friends = settings.lock().unwrap().friends.clone();
                        for friend in friends.values() {
                            let target = format!("{}:{}", friend.ip, friend.port);
                            if let Ok(data) = bincode::serialize(&packet) {
                                let cipher = ChaCha20Poly1305::new(k.into());
                                let mut nonce = [0u8; 12];
                                rand::thread_rng().fill_bytes(&mut nonce);
                                if let Ok(ct) = cipher.encrypt(Nonce::from_slice(&nonce), data.as_ref()) {
                                    let mut pkt = nonce.to_vec();
                                    pkt.extend_from_slice(&ct);
                                    let _ = sock.send_to(&pkt, target).await;
                                }
                            }
                        }
                        if let PacketType::Chat(text) = packet.p_type {
                            chat.lock().unwrap().push((packet.sender, text));
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
                    if let (Some((pkt, addr)), Some(k)) = (res, &key) {
                        if pkt.len() > 12 {
                            let nonce = Nonce::from_slice(&pkt[..12]);
                            let cipher = ChaCha20Poly1305::new(k.into());
                            if let Ok(pt) = cipher.decrypt(nonce, &pkt[12..]) {
                                if let Ok(packet) = bincode::deserialize::<SecurePacket>(&pt) {
                                    match packet.p_type {
                                        PacketType::Chat(text) => chat.lock().unwrap().push((packet.sender, text)),
                                        PacketType::Ping => {
                                            let mut s = settings.lock().unwrap();
                                            if let Some(f) = s.friends.values_mut().find(|f| f.ip == addr.ip().to_string()) {
                                                f.is_online = true;
                                                f.last_seen = Some(chrono::Utc::now());
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });
}

#[tokio::main]
async fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([800.0, 600.0]),
        ..Default::default()
    };
    eframe::run_native("MicroSync Ultra", options, Box::new(|cc| Box::new(MicroSyncApp::new(cc))))
}
