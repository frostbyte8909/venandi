use axum_governor::{GovernorConfigBuilder, GovernorLayer, extractor::PeerIp};
use governor::Quota;
use std::num::NonZeroU32;

fn main() {
    let auth_quota = Quota::per_minute(NonZeroU32::new(5).unwrap());
    let _cfg = GovernorConfigBuilder::default()
        .with_extractor(PeerIp::default())
        .expect_connect_info()
        .quota_default(auth_quota)
        .finish()
        .unwrap();
    println!("Compiled!");
}
