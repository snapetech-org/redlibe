use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use aes::Aes128;
use aes_gcm::{
	aead::{Aead, KeyInit},
	Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use cbc::cipher::{block_padding::Pkcs7, BlockModeDecrypt, KeyIvInit};
use pbkdf2::pbkdf2_hmac;
use rusqlite::Connection;
use serde_json::Value;
use sha1::Sha1;
use uuid::Uuid;

use super::{ImportedBrowserSession, LocalProfile};

type Aes128CbcDec = cbc::Decryptor<Aes128>;

pub fn discover_profiles(browser: &str) -> Vec<LocalProfile> {
	let Some(base) = chromium_user_data_dir(browser) else {
		return Vec::new();
	};
	discover_profiles_in_base(browser, &base)
}

pub fn discover_profiles_in_base(browser: &str, base: &Path) -> Vec<LocalProfile> {
	let mut out = Vec::new();
	let entries = match fs::read_dir(&base) {
		Ok(v) => v,
		Err(_) => return out,
	};

	for entry in entries.flatten() {
		let path = entry.path();
		if !path.is_dir() {
			continue;
		}
		let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
		if name != "Default" && !name.starts_with("Profile ") {
			continue;
		}
		let cookies = path.join("Cookies");
		if !cookies.is_file() {
			continue;
		}
		let id = format!("{browser}:{name}");
		let label = format!("{} ({name})", display_browser(browser));
		out.push(LocalProfile {
			browser: browser.to_string(),
			id,
			label,
			path,
		});
	}
	out
}

pub fn import_token(browser: &str, profile_id: Option<&str>, profile_path: Option<&str>) -> Result<ImportedBrowserSession, String> {
	let profile = resolve_profile(browser, profile_id, profile_path)?;
	log::info!("Chromium local import: browser={} profile={}", browser, profile.display());
	let db_path = profile.join("Cookies");
	if !db_path.is_file() {
		return Err(format!("Cookies DB not found in {}", profile.display()));
	}
	let tmp = copy_to_temp(&db_path)?;
	let _cleanup = TempFileCleanup(tmp.clone());
	let conn = Connection::open(&tmp).map_err(|e| format!("Failed to open Chromium cookie DB: {e}"))?;

	let row = read_chromium_cookie(&conn)?;
	let token = if !row.value.is_empty() {
		log::info!("Chromium local import: using plaintext cookie value");
		row.value
	} else if !row.encrypted_value.is_empty() {
		log::info!("Chromium local import: encrypted cookie detected ({} bytes), attempting decrypt", row.encrypted_value.len());
		decrypt_chromium_cookie(browser, &profile, &row)?
	} else {
		return Err("No reddit token_v2 cookie found in selected Chromium profile".to_string());
	};

	Ok(ImportedBrowserSession {
		bearer_token: token,
		user_agent: None,
	})
}

#[derive(Debug)]
struct ChromiumCookieRow {
	value: String,
	encrypted_value: Vec<u8>,
	host_key: String,
}

struct TempFileCleanup(PathBuf);
impl Drop for TempFileCleanup {
	fn drop(&mut self) {
		let _ = fs::remove_file(&self.0);
	}
}

fn copy_to_temp(path: &Path) -> Result<PathBuf, String> {
	let tmp = env::temp_dir().join(format!("redlib-chromium-cookies-{}.sqlite", Uuid::new_v4()));
	fs::copy(path, &tmp).map_err(|e| format!("Failed to copy cookie DB: {e}"))?;
	Ok(tmp)
}

fn read_chromium_cookie(conn: &Connection) -> Result<ChromiumCookieRow, String> {
	let mut stmt = conn
		.prepare(
			"SELECT COALESCE(value, ''), encrypted_value, host_key
			 FROM cookies
			 WHERE name = 'token_v2'
			   AND host_key LIKE '%reddit.com'
			 ORDER BY last_access_utc DESC
			 LIMIT 1",
		)
		.map_err(|e| format!("Failed to prepare Chromium cookie query: {e}"))?;

	stmt
		.query_row([], |row| {
			Ok(ChromiumCookieRow {
				value: row.get(0)?,
				encrypted_value: row.get(1)?,
				host_key: row.get(2)?,
			})
		})
		.map_err(|_| "No reddit token_v2 cookie found in selected Chromium profile".to_string())
}

fn decrypt_chromium_cookie(browser: &str, profile_dir: &Path, row: &ChromiumCookieRow) -> Result<String, String> {
	let enc = &row.encrypted_value;
	if enc.is_empty() {
		return Err("Encrypted cookie value was empty".to_string());
	}

	// Newer Chromium cookie format: version prefix + AES-GCM payload.
	if enc.starts_with(b"v10") || enc.starts_with(b"v11") {
		log::info!(
			"Chromium local import: cookie prefix={} (modern/legacy tagged format)",
			String::from_utf8_lossy(&enc[..3.min(enc.len())])
		);
		if let Some(master_key) = try_get_modern_master_key(browser, profile_dir)? {
			log::info!("Chromium local import: trying AES-GCM with Local State master key");
			if let Ok(plain) = decrypt_cookie_gcm(enc, &master_key, &row.host_key) {
				log::info!("Chromium local import: AES-GCM decryption succeeded");
				return Ok(plain);
			}
			log::warn!("Chromium local import: AES-GCM decryption failed after obtaining Local State key");
		}

		// Linux/macOS older Chromium can also use v10/v11 with legacy AES-CBC key derivation.
		if let Some(pass) = try_get_legacy_password(browser) {
			log::info!("Chromium local import: trying legacy AES-CBC decryption");
			if let Ok(plain) = decrypt_cookie_legacy_cbc(enc, &pass, legacy_pbkdf2_iterations(), &row.host_key) {
				log::info!("Chromium local import: legacy AES-CBC decryption succeeded");
				return Ok(plain);
			}
			log::warn!("Chromium local import: legacy AES-CBC decryption failed");
		}

		return Err(
			"Chromium token is encrypted and could not be decrypted. Try Firefox/LibreWolf local import, or provide a profile from an unlocked browser session on the same machine."
				.to_string(),
		);
	}

	// Some Chromium builds store legacy AES-CBC values without a v10/v11 prefix.
	if let Some(pass) = try_get_legacy_password(browser) {
		log::info!("Chromium local import: trying untagged legacy AES-CBC decryption");
		if let Ok(plain) = decrypt_cookie_legacy_cbc(enc, &pass, legacy_pbkdf2_iterations(), &row.host_key) {
			log::info!("Chromium local import: untagged legacy AES-CBC decryption succeeded");
			return Ok(plain);
		}
		log::warn!("Chromium local import: untagged legacy AES-CBC decryption failed");
	}

	Err("Unsupported Chromium cookie encryption format".to_string())
}

fn decrypt_cookie_gcm(enc: &[u8], key: &[u8], host_key: &str) -> Result<String, String> {
	if key.len() != 32 {
		return Err("Chromium master key is not 32 bytes".to_string());
	}
	if enc.len() < 3 + 12 + 16 {
		return Err("Encrypted Chromium cookie payload is too short".to_string());
	}
	let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("Invalid GCM key: {e}"))?;
	let nonce = Nonce::from_slice(&enc[3..15]);
	let ciphertext = &enc[15..];
	let plain = cipher.decrypt(nonce, ciphertext).map_err(|_| "AES-GCM decryption failed".to_string())?;
	decode_cookie_plaintext(&plain, host_key)
}

fn decrypt_cookie_legacy_cbc(enc: &[u8], password: &str, iterations: u32, host_key: &str) -> Result<String, String> {
	let decrypted = decrypt_legacy_cbc_bytes(enc, password, iterations)?;
	decode_cookie_plaintext(&decrypted, host_key)
}

fn decrypt_legacy_cbc_bytes(enc: &[u8], password: &str, iterations: u32) -> Result<Vec<u8>, String> {
	let cipher_bytes = if enc.starts_with(b"v10") || enc.starts_with(b"v11") { &enc[3..] } else { enc };
	let mut key = [0u8; 16];
	pbkdf2_hmac::<Sha1>(password.as_bytes(), b"saltysalt", iterations, &mut key);
	let iv = [b' '; 16];
	let mut buf = cipher_bytes.to_vec();
	let decrypted = Aes128CbcDec::new((&key).into(), (&iv).into())
		.decrypt_padded::<Pkcs7>(&mut buf)
		.map_err(|_| "AES-CBC decryption failed".to_string())?;
	Ok(decrypted.to_vec())
}

fn decode_cookie_plaintext(bytes: &[u8], host_key: &str) -> Result<String, String> {
	if let Ok(s) = std::str::from_utf8(bytes) {
		let trimmed = s.trim_matches('\0').to_string();
		if is_plausible_token(&trimmed) {
			return Ok(trimmed);
		}
	}

	// Chromium DB v24+ may prefix the plaintext with SHA-256(host_key).
	if bytes.len() > 32 {
		if let Ok(s) = std::str::from_utf8(&bytes[32..]) {
			let trimmed = s.trim_matches('\0').to_string();
			if is_plausible_token(&trimmed) {
				return Ok(trimmed);
			}
		}
	}

	Err(format!("Decrypted cookie did not look like a token for host {}", host_key))
}

fn is_plausible_token(s: &str) -> bool {
	!s.is_empty() && (s.split('.').count() >= 2 || s.starts_with("Bearer ") || s.chars().all(|c| c.is_ascii_graphic()))
}

fn try_get_modern_master_key(browser: &str, profile_dir: &Path) -> Result<Option<Vec<u8>>, String> {
	let Some(user_data_dir) = profile_dir.parent() else {
		return Ok(None);
	};
	let local_state = user_data_dir.join("Local State");
	if !local_state.is_file() {
		log::info!("Chromium local import: Local State not found at {}", local_state.display());
		return Ok(None);
	}
	let contents = fs::read_to_string(&local_state).map_err(|e| format!("Failed to read Local State: {e}"))?;
	let json: Value = serde_json::from_str(&contents).map_err(|e| format!("Failed to parse Local State: {e}"))?;
	let b64 = match json.get("os_crypt").and_then(|v| v.get("encrypted_key")).and_then(Value::as_str) {
		Some(v) if !v.is_empty() => v,
		_ => {
			log::info!("Chromium local import: Local State has no os_crypt.encrypted_key");
			return Ok(None);
		}
	};
	let raw = general_purpose::STANDARD.decode(b64).map_err(|e| format!("Invalid Local State encrypted_key: {e}"))?;
	log::info!("Chromium local import: found Local State encrypted_key ({} bytes)", raw.len());
	decrypt_local_state_key(browser, &raw).map(Some)
}

fn decrypt_local_state_key(browser: &str, raw: &[u8]) -> Result<Vec<u8>, String> {
	#[cfg(target_os = "windows")]
	{
		log::info!("Chromium local import: unwrapping Local State key via Windows DPAPI");
		return decrypt_local_state_key_windows(raw);
	}
	#[cfg(target_os = "macos")]
	{
		log::info!("Chromium local import: attempting macOS Local State key unwrap via Safe Storage password");
		return decrypt_local_state_key_with_safe_storage_password(browser, raw, 1003);
	}
	#[cfg(not(any(target_os = "windows", target_os = "macos")))]
	{
		// Linux Chromium varies by build. Some environments expose an unwrapped key in Local State;
		// others require Secret Service. Try raw 32-byte first, then Safe Storage style unwrap.
		if raw.starts_with(b"DPAPI") {
			log::warn!("Chromium local import: Local State key has DPAPI prefix on non-Windows host");
			return Err("Linux Local State key used Windows DPAPI prefix unexpectedly".to_string());
		}
		if raw.len() == 32 {
			log::info!("Chromium local import: treating Linux Local State key as raw 32-byte key");
			return Ok(raw.to_vec());
		}
		if raw.starts_with(b"v10") || raw.starts_with(b"v11") {
			log::info!("Chromium local import: attempting Linux Local State key unwrap via Secret Service/legacy password");
			return decrypt_local_state_key_with_safe_storage_password(browser, raw, 1);
		}
		Err(format!("Unsupported Linux Local State key format ({} bytes)", raw.len()))
	}
}

#[cfg(target_os = "windows")]
fn decrypt_local_state_key_windows(raw: &[u8]) -> Result<Vec<u8>, String> {
	let dpapi_blob = raw.strip_prefix(b"DPAPI").unwrap_or(raw);
	let b64 = general_purpose::STANDARD.encode(dpapi_blob);
	let ps = format!(
		r#"$b=[Convert]::FromBase64String('{b64}'); $o=[System.Security.Cryptography.ProtectedData]::Unprotect($b,$null,[System.Security.Cryptography.DataProtectionScope]::CurrentUser); [Console]::Write([Convert]::ToBase64String($o))"#
	);
	let output = Command::new("powershell")
		.args(["-NoProfile", "-NonInteractive", "-Command", &ps])
		.output()
		.map_err(|e| format!("Failed to invoke PowerShell for DPAPI decrypt: {e}"))?;
	if !output.status.success() {
		return Err(format!("PowerShell DPAPI decrypt failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
	}
	let out = String::from_utf8_lossy(&output.stdout);
	let trimmed = out.trim();
	general_purpose::STANDARD.decode(trimmed).map_err(|e| format!("Failed to decode DPAPI output: {e}"))
}

fn try_get_legacy_password(browser: &str) -> Option<String> {
	#[cfg(target_os = "macos")]
	{
		for service in mac_safe_storage_service_candidates(browser) {
			log::info!("Chromium local import: trying macOS Keychain lookup for {}", service);
			let output = Command::new("security").args(["find-generic-password", "-w", "-s", service]).output().ok()?;
			if output.status.success() {
				let pwd = String::from_utf8_lossy(&output.stdout).trim().to_string();
				if !pwd.is_empty() {
					log::info!("Chromium local import: macOS Keychain lookup succeeded for {}", service);
					return Some(pwd);
				}
			}
		}
		log::warn!("Chromium local import: macOS Keychain lookup failed for all services");
		None
	}
	#[cfg(not(target_os = "macos"))]
	{
		#[cfg(not(target_os = "windows"))]
		{
			for app in linux_secret_tool_application_candidates(browser) {
				log::info!("Chromium local import: trying secret-tool lookup for application={}", app);
				let output = Command::new("secret-tool").args(["lookup", "application", app]).output().ok()?;
				if output.status.success() {
					let pwd = String::from_utf8_lossy(&output.stdout).trim().to_string();
					if !pwd.is_empty() {
						log::info!("Chromium local import: secret-tool lookup succeeded for application={}", app);
						return Some(pwd);
					}
				}
			}
			// Historical fallback used by some Chromium/Linux setups without keyring integration.
			log::warn!("Chromium local import: secret-tool lookup unavailable/failed; falling back to legacy 'peanuts' password");
			return Some("peanuts".to_string());
		}
		#[cfg(target_os = "windows")]
		{
			None
		}
	}
}

fn decrypt_local_state_key_with_safe_storage_password(browser: &str, raw: &[u8], iterations: u32) -> Result<Vec<u8>, String> {
	let password = try_get_legacy_password(browser).ok_or_else(|| "No Safe Storage password available for Local State key unwrap".to_string())?;
	let decrypted = decrypt_legacy_cbc_bytes(raw, &password, iterations)?;
	if decrypted.len() == 32 {
		log::info!("Chromium local import: Local State key unwrap via Safe Storage password succeeded");
		return Ok(decrypted);
	}
	if decrypted.len() > 32 {
		// Some variants may prefix metadata before the key.
		let tail = &decrypted[decrypted.len() - 32..];
		log::warn!(
			"Chromium local import: Local State unwrap produced {} bytes; using trailing 32 bytes as key",
			decrypted.len()
		);
		return Ok(tail.to_vec());
	}
	Err(format!("Local State unwrap produced {} bytes, expected at least 32", decrypted.len()))
}

fn legacy_pbkdf2_iterations() -> u32 {
	if cfg!(target_os = "macos") {
		1003
	} else {
		1
	}
}

#[cfg(target_os = "macos")]
fn mac_safe_storage_service_candidates(browser: &str) -> &'static [&'static str] {
	match browser {
		"edge" => &["Microsoft Edge Safe Storage"],
		_ => &["Chrome Safe Storage", "Chromium Safe Storage"],
	}
}

#[cfg(not(target_os = "windows"))]
fn linux_secret_tool_application_candidates(browser: &str) -> &'static [&'static str] {
	match browser {
		"edge" => &["microsoft-edge", "Microsoft Edge", "chrome"],
		_ => &["chrome", "google-chrome", "chromium", "Chromium"],
	}
}

fn resolve_profile(browser: &str, profile_id: Option<&str>, profile_path: Option<&str>) -> Result<PathBuf, String> {
	if let Some(path) = profile_path.map(str::trim).filter(|s| !s.is_empty()) {
		return Ok(PathBuf::from(path));
	}

	if let Some(id) = profile_id {
		for p in discover_profiles(browser) {
			if p.id == id {
				return Ok(p.path);
			}
		}
		return Err("Selected profile was not found".to_string());
	}

	discover_profiles(browser)
		.into_iter()
		.next()
		.map(|p| p.path)
		.ok_or_else(|| format!("No {} profiles with Cookies DB were found", display_browser(browser)))
}

fn display_browser(browser: &str) -> &'static str {
	match browser {
		"edge" => "Edge",
		_ => "Chrome",
	}
}

fn chromium_user_data_dir(browser: &str) -> Option<PathBuf> {
	if cfg!(target_os = "windows") {
		let local = env::var_os("LOCALAPPDATA")?;
		let mut p = PathBuf::from(local);
		match browser {
			"edge" => {
				p.push("Microsoft");
				p.push("Edge");
				p.push("User Data");
			}
			_ => {
				p.push("Google");
				p.push("Chrome");
				p.push("User Data");
			}
		}
		return Some(p);
	}

	if cfg!(target_os = "macos") {
		let home = env::var_os("HOME")?;
		let mut p = PathBuf::from(home);
		p.push("Library");
		p.push("Application Support");
		match browser {
			"edge" => p.push("Microsoft Edge"),
			_ => {
				p.push("Google");
				p.push("Chrome");
			}
		}
		return Some(p);
	}

	let home = env::var_os("HOME")?;
	let mut p = PathBuf::from(home);
	p.push(".config");
	match browser {
		"edge" => p.push("microsoft-edge"),
		_ => p.push("google-chrome"),
	}
	Some(p)
}

#[cfg(test)]
mod cbc_compatibility_tests {
	use super::decrypt_legacy_cbc_bytes;
	#[test]
	fn reads_independent_openssl_chromium_fixture() {
		// Synthetic PBKDF2-SHA1/space-IV fixture generated independently with OpenSSL.
		let ciphertext: &[u8] = &[
			149, 86, 207, 147, 234, 191, 149, 13, 72, 110, 177, 142, 207, 34, 22, 135, 157, 36, 182, 216, 194, 169, 184, 207, 180, 57, 45, 20, 61, 151, 56, 161,
		];
		let mut encoded = b"v10".to_vec();
		encoded.extend_from_slice(ciphertext);
		assert_eq!(decrypt_legacy_cbc_bytes(&encoded, "fixture-password", 1).unwrap(), b"non-secret chromium fixture");
	}
	#[test]
	fn rejects_malformed_cbc_block_length() {
		assert!(decrypt_legacy_cbc_bytes(&[0; 15], "fixture-password", 1).is_err());
	}
}
