use std::path::Path;
use std::process::{Child, Command};
use std::thread::sleep;
use std::time::Duration;

#[allow(dead_code)]
#[derive(Debug)]
pub struct SoloVirtualKey {
    handle: Child,
}

impl Default for SoloVirtualKey {
    fn default() -> Self {
        let key_path = env!("OUT_DIR");
        let binary = Path::new(key_path).join("solokey");
        if !binary.exists() {
            panic!("Binary not found at path {:?}", binary);
        }

        let handle = Command::new(binary)
            .current_dir(key_path)
            .spawn()
            .expect("failed to start virtual key binary");

        sleep(Duration::from_millis(50));
        Self { handle }
    }
}

impl Drop for SoloVirtualKey {
    fn drop(&mut self) {
        self.handle.kill().unwrap();
    }
}
