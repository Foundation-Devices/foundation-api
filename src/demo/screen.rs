use std::{sync::Arc, time::Duration};
use tokio::sync::{Mutex, Notify};
use bc_envelope::prelude::*;

#[derive(Debug)]
pub struct ScreenPeers {
    screen: Arc<Screen>,
    camera: Arc<Camera>,
}

impl ScreenPeers {
    pub fn new(screen_prefix: &str, camera_prefix: &str) -> Self {
        let screen = Screen::new(screen_prefix);
        let camera = Camera::new(&screen, camera_prefix);
        Self {
            screen,
            camera,
        }
    }

    pub fn screen(&self) -> &Arc<Screen> {
        &self.screen
    }

    pub fn camera(&self) -> &Arc<Camera> {
        &self.camera
    }
}

#[derive(Debug)]
pub struct ScreenGuard {
    screen: Arc<Screen>,
}

impl ScreenGuard {
    pub fn new(screen: &Arc<Screen>) -> Self {
        Self {
            screen: screen.clone()
        }
    }
}

impl Drop for ScreenGuard {
    fn drop(&mut self) {
        let screen = self.screen.clone();
        tokio::spawn(async move {
            //println!("Dropping ScreenGuard");
            screen.clear().await;
        });
    }
}

#[derive(Debug)]
pub struct Screen {
    prefix: String,
    data: Mutex<Option<String>>,
    notify: Notify,
}

impl Screen {
    pub fn new(prefix: &str) -> Arc<Self> {
        Arc::new(Screen {
            prefix: prefix.to_string(),
            data: Mutex::new(None),
            notify: Notify::new(),
        })
    }

    pub async fn show(self: Arc<Self>, data: String) -> ScreenGuard {
        *self.data.lock().await = Some(data);
        self.notify.notify_waiters();
        ScreenGuard::new(&self)
    }

    pub async fn clear(self: Arc<Self>) {
        *self.data.lock().await = None;
        self.notify.notify_waiters();
        println!("{} 📺 Screen cleared", self.prefix);
    }

    pub async fn show_envelope(self: Arc<Self>, envelope: &Envelope) -> ScreenGuard {
        let data = envelope.ur_string().to_uppercase();
        self.show(data).await
    }
}

// Internal methods
impl Screen {
    pub fn data(&self) -> &Mutex<Option<String>> {
        &self.data
    }

    pub fn notify(&self) -> &Notify {
        &self.notify
    }
}

#[derive(Debug)]
pub struct Camera {
    _prefix: String,
    screen: Arc<Screen>,
}

#[derive(Debug, thiserror::Error)]
pub enum CameraError {
    #[error("No QR code read")]
    NoQrCode,
}

impl Camera {
    pub fn new(screen: &Arc<Screen>, prefix: &str) -> Arc<Self> {
        Arc::new(Camera {
            _prefix: prefix.to_string(),
            screen: screen.clone()
        })
    }

    async fn poll_visible(&self) -> Option<String> {
        self.screen.data().lock().await.clone()
    }

    pub async fn scan_envelope(&self, duration: Duration) -> anyhow::Result<Envelope> {
        let string = self.scan_qr_code(duration).await;
        if string.is_none() {
            return Err(CameraError::NoQrCode.into());
        }
        let string = string.unwrap();
        Envelope::from_ur_string(string)
    }

    pub async fn scan_qr_code(&self, timeout: Duration) -> Option<String> {
        let mut current = self.poll_visible().await;
        if current.is_some() {
            return current;
        }

        let mut notify_guard = Box::pin(self.screen.notify().notified());
        tokio::select! {
            _ = tokio::time::sleep(timeout) => {}
            _ = &mut notify_guard => {
                current = self.poll_visible().await;
            }
        }

        current
    }
}
