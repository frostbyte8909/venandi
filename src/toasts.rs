use rand::seq::SliceRandom;
use serde::Deserialize;
use std::{collections::HashMap, fs, path::Path, sync::RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ToastTrigger {
    CorrectFlag,
    NearMiss,
    WrongFlag,
    CanaryTriggered,
    RateLimited,
}

#[derive(Debug, Deserialize, Default)]
struct ToastConfig {
    triggers: HashMap<String, TriggerVariants>,
}

#[derive(Debug, Deserialize)]
struct TriggerVariants {
    variants: Vec<String>,
}

pub struct ToastRegistry {
    config: RwLock<ToastConfig>,
}

impl ToastRegistry {
    pub fn new<P: AsRef<Path>>(config_path: P) -> Self {
        let registry = Self {
            config: RwLock::new(ToastConfig::default()),
        };
        registry.reload(config_path);
        registry
    }

    pub fn reload<P: AsRef<Path>>(&self, config_path: P) {
        let Ok(content) = fs::read_to_string(config_path) else { return };
        let Ok(parsed) = toml::from_str::<ToastConfig>(&content) else { return };
        if let Ok(mut guard) = self.config.write() {
            *guard = parsed;
        }
    }

    pub fn get(&self, trigger: ToastTrigger) -> String {
        let key = match trigger {
            ToastTrigger::CorrectFlag => "correct_flag",
            ToastTrigger::NearMiss => "near_miss",
            ToastTrigger::WrongFlag => "wrong_flag",
            ToastTrigger::CanaryTriggered => "canary_triggered",
            ToastTrigger::RateLimited => "rate_limited",
        };

        if let Ok(guard) = self.config.read() {
            if let Some(group) = guard.triggers.get(key) {
                let mut rng = rand::thread_rng();
                if let Some(msg) = group.variants.choose(&mut rng) {
                    return msg.clone();
                }
            }
        }

        // Hardcoded fallbacks; never exposed as a cold-start failure.
        match trigger {
            ToastTrigger::CorrectFlag => "Flag accepted.".to_string(),
            ToastTrigger::NearMiss => "You're close!".to_string(),
            ToastTrigger::WrongFlag => "Incorrect flag.".to_string(),
            ToastTrigger::CanaryTriggered => "Security violation detected.".to_string(),
            ToastTrigger::RateLimited => "Too many requests.".to_string(),
        }
    }
}
