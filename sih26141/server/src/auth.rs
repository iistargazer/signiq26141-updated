//! Per-user accounts for the document layer: register / login / token
//! sessions, and an optional-auth extractor so every doc handler can scope
//! its state (session key, inbox, last seal) to the logged-in user.
//!
//! Design notes:
//! * Passwords are stored as PBKDF2-HMAC-SHA256 digests (600_000 rounds,
//!   16-byte random salt, hex) — never plaintext. Derivation uses the same
//!   SHA-256/HMAC primitives the rest of the framework ships (a compact
//!   PBKDF2 implementation over `hmac::Hmac<Sha256>`), no new crypto crate.
//! * Sessions are random 256-bit bearer tokens; the token is returned once
//!   at login and kept in memory only (clients store it; the server never
//!   persists tokens to disk).
//! * `users.json` (path overridable via `USERS_FILE`) survives restarts so
//!   accounts are durable. Login failures are rate-limited with a simple
//!   per-username backoff to blunt online guessing during demos.
//! * `AuthUser` implements `FromRequestParts` with `Rejection = AuthError`;
//!   handlers that accept `user: AuthUser` REQUIRE login (401 otherwise).

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::Json;
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

type HmacSha256 = Hmac<Sha256>;

const PBKDF2_ROUNDS: u32 = 600_000;
const SALT_LEN: usize = 16;
const TOKEN_LEN: usize = 32;
const MAX_USERNAME: usize = 32;
const MAX_USERS: usize = 256;
/// Login backoff after a failed attempt (per username).
const LOGIN_BACKOFF: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------------------
// Password hashing (PBKDF2-HMAC-SHA256, compact implementation)
// ---------------------------------------------------------------------------

fn pbkdf2_sha256(password: &[u8], salt: &[u8], rounds: u32) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(password).expect("HMAC accepts any key length");
    mac.update(salt);
    mac.update(&(1u32).to_be_bytes());
    let mut u = mac.finalize().into_bytes();
    let mut t = [0u8; 32];
    t.copy_from_slice(&u);
    for _ in 1..rounds {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(password).expect("HMAC accepts any key length");
        mac.update(&u);
        u = mac.finalize().into_bytes();
        for (tb, ub) in t.iter_mut().zip(u.iter()) {
            *tb ^= ub;
        }
    }
    t
}

fn hash_password(password: &str, salt: &[u8]) -> String {
    hex::encode(pbkdf2_sha256(password.as_bytes(), salt, PBKDF2_ROUNDS))
}

/// Constant-time comparison via the `subtle` crate (already a dependency
/// of `sealing`, re-exported here through the server's direct dep).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}

// ---------------------------------------------------------------------------
// Persisted user records + in-memory sessions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserRecord {
    pub username: String,
    /// Hex salt (SALT_LEN bytes).
    pub salt: String,
    /// Hex PBKDF2 digest.
    pub password_hash: String,
    pub created_at: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct UserStore {
    users: Vec<UserRecord>,
}

/// In-memory session table: token -> username. Sessions die with the
/// process (tokens are never persisted).
#[derive(Default)]
pub struct Sessions {
    map: Mutex<HashMap<String, String>>,
    /// Per-username last failed-login instant (backoff).
    last_fail: Mutex<HashMap<String, Instant>>,
}

pub struct AuthState {
    pub users_path: PathBuf,
    store: Mutex<UserStore>,
    pub sessions: Sessions,
}

impl AuthState {
    pub fn load(users_path: PathBuf) -> Self {
        let store = match std::fs::read_to_string(&users_path) {
            Ok(text) => serde_json::from_str::<UserStore>(&text).unwrap_or_default(),
            Err(_) => UserStore::default(),
        };
        Self { users_path, store: Mutex::new(store), sessions: Sessions::default() }
    }

    fn persist(&self, store: &UserStore) -> Result<(), String> {
        let tmp = self.users_path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(store).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        std::fs::rename(&tmp, &self.users_path).map_err(|e| e.to_string())
    }

    pub fn register(&self, username: &str, password: &str, now: &str) -> Result<(), String> {
        let username = username.trim();
        if username.is_empty() || username.len() > MAX_USERNAME {
            return Err("username must be 1..32 chars".into());
        }
        if !username.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-') {
            return Err("username may contain letters, digits, '_' and '-' only".into());
        }
        if password.len() < 6 {
            return Err("password must be at least 6 characters".into());
        }
        let mut store = self.store.lock().map_err(|_| "auth lock poisoned")?;
        if store.users.iter().any(|u| u.username == username) {
            return Err("username already taken".into());
        }
        if store.users.len() >= MAX_USERS {
            return Err("user limit reached (demo scope)".into());
        }
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill(&mut salt);
        let record = UserRecord {
            username: username.to_string(),
            salt: hex::encode(salt),
            password_hash: hash_password(password, &salt),
            created_at: now.to_string(),
        };
        store.users.push(record);
        self.persist(&store)
    }

    /// Verify credentials and issue a bearer token. Applies a small backoff
    /// per username after failures. Returns the token or an error message.
    pub fn login(&self, username: &str, password: &str) -> Result<String, String> {
        let username = username.trim();
        {
            let fails = self.sessions.last_fail.lock().map_err(|_| "auth lock poisoned")?;
            if let Some(t) = fails.get(username) {
                if t.elapsed() < LOGIN_BACKOFF {
                    return Err("too many attempts — wait a moment".into());
                }
            }
        }
        let record = {
            let store = self.store.lock().map_err(|_| "auth lock poisoned")?;
            store.users.iter().find(|u| u.username == username).cloned()
        };
        let ok = match record {
            Some(r) => {
                let salt = hex::decode(&r.salt).unwrap_or_default();
                let candidate = hash_password(password, &salt);
                ct_eq(candidate.as_bytes(), r.password_hash.as_bytes())
            }
            None => {
                // Equalize timing for unknown users (hash a dummy).
                let _ = hash_password(password, &[0u8; SALT_LEN]);
                false
            }
        };
        if !ok {
            if let Ok(mut fails) = self.sessions.last_fail.lock() {
                fails.insert(username.to_string(), Instant::now());
            }
            return Err("invalid username or password".into());
        }
        let mut token_bytes = [0u8; TOKEN_LEN];
        rand::thread_rng().fill(&mut token_bytes);
        let token = hex::encode(token_bytes);
        self.sessions
            .map
            .lock()
            .map_err(|_| "auth lock poisoned")?
            .insert(token.clone(), username.to_string());
        Ok(token)
    }

    pub fn username_for(&self, token: &str) -> Option<String> {
        self.sessions.map.lock().ok()?.get(token).cloned()
    }

    pub fn logout(&self, token: &str) {
        if let Ok(mut map) = self.sessions.map.lock() {
            map.remove(token);
        }
    }

    pub fn user_count(&self) -> usize {
        self.store.lock().map(|s| s.users.len()).unwrap_or(0)
    }

    /// All registered usernames (the address book behind the send UI).
    pub fn registered_users(&self) -> Vec<String> {
        self.store
            .lock()
            .map(|s| {
                let mut names: Vec<String> = s.users.iter().map(|u| u.username.clone()).collect();
                names.sort();
                names
            })
            .unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// Extractor: require a valid bearer token
// ---------------------------------------------------------------------------

/// Extraction failure mapped to 401 (with the auth layer's error message).
#[derive(Debug)]
pub struct AuthError;

impl axum::response::IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "authentication required" })),
        )
            .into_response()
    }
}

/// Request guard: the handler runs only for a logged-in user. Reads the
/// `Authorization: Bearer <token>` header (or `?token=` for SSE links).
pub struct AuthUser(pub String);

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync + AsRef<AuthState>,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = state.as_ref();
        let token = extract_token(parts).ok_or(AuthError)?;
        let username = auth_state.username_for(&token).ok_or(AuthError)?;
        Ok(AuthUser(username))
    }
}

/// Optional variant: yields `Some(username)` when a valid token is present,
/// `None` otherwise. Never rejects — used by endpoints that serve both the
/// logged-in dashboard and anonymous scripts (e.g. /api/run).
pub struct OptionalAuth(pub Option<String>);

impl<S> FromRequestParts<S> for OptionalAuth
where
    S: Send + Sync + AsRef<AuthState>,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let auth_state = state.as_ref();
        let username = extract_token(parts).and_then(|t| auth_state.username_for(&t));
        Ok(OptionalAuth(username))
    }
}

fn extract_token(parts: &Parts) -> Option<String> {
    parts
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(String::from)
        .or_else(|| {
            parts.uri.query().and_then(|q| {
                q.split('&').find_map(|kv| {
                    let (k, v) = kv.split_once('=')?;
                    (k == "token").then(|| v.to_string())
                })
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pbkdf2_known_vector() {
        // RFC 6070-style sanity (SHA-256 variant): deterministic digest.
        let a = pbkdf2_sha256(b"password", b"salt", 4096);
        let b = pbkdf2_sha256(b"password", b"salt", 4096);
        let c = pbkdf2_sha256(b"Password", b"salt", 4096);
        assert_eq!(a, b);
        assert_ne!(a, c);
        // Well-known digest for PBKDF2-HMAC-SHA256("password","salt",1):
        let one = pbkdf2_sha256(b"password", b"salt", 1);
        assert_eq!(
            hex::encode(one),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }

    #[test]
    fn register_login_round_trip() {
        let dir = std::env::temp_dir().join("auth_test_users");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("users.json");
        let _ = std::fs::remove_file(&path);
        let auth = AuthState::load(path.clone());

        auth.register("alice", "secret123", "t").expect("register");
        assert!(auth.register("alice", "other66", "t").is_err(), "duplicate rejected");
        assert!(auth.register("bob", "abc", "t").is_err(), "short password rejected");

        let token = auth.login("alice", "secret123").expect("login");
        assert_eq!(auth.username_for(&token).as_deref(), Some("alice"));
        assert!(auth.login("alice", "wrong!!1").is_err(), "wrong password rejected");
        assert!(auth.login("eve", "whatever1").is_err(), "unknown user rejected");
        assert_eq!(auth.user_count(), 1);

        // Reload from disk: the account survives.
        let reloaded = AuthState::load(path.clone());
        assert_eq!(reloaded.user_count(), 1);
        let t2 = reloaded.login("alice", "secret123").expect("login after reload");
        assert_eq!(reloaded.username_for(&t2).as_deref(), Some("alice"));
        // Tokens do NOT survive reload (session table is memory-only).
        assert_eq!(reloaded.username_for(&token), None);
        let _ = std::fs::remove_file(&path);
    }
}
