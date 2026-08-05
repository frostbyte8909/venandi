use axum::{extract::Request, response::Response};
use tower_governor::{
    governor::GovernorConfigBuilder, key_extractor::KeyExtractor, GovernorError,
};

#[derive(Clone, Copy)]
pub struct AuthOrIpKeyExtractor;

impl KeyExtractor for AuthOrIpKeyExtractor {
    type Key = String;

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        // Just extract IP for now to keep it simple and compile-safe
        req.extensions()
            .get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
            .map(|c| c.0.ip().to_string())
            .ok_or(GovernorError::ExtractorError("missing IP".into()))
    }
    
    fn key_name(&self, key: &Self::Key) -> Option<String> {
        Some(key.clone())
    }
    fn name(&self) -> &'static str {
        "auth_or_ip"
    }
}
