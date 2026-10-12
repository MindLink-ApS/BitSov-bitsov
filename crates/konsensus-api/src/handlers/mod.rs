//! API route handlers.

pub mod auth_routes;
pub mod browse;
pub mod calendar;
pub mod chain;
pub mod content;
pub mod device_routes;
pub mod export;
pub mod files;
pub mod front_door;
pub mod gossip;
pub mod health;
pub mod hosting;
pub mod identity;
pub mod introduction;
pub mod invite;
pub mod invites;
pub mod messages;
pub mod onboarding;
pub mod organism;
pub(crate) mod owner_approval_routes;
pub(crate) mod owner_device_routes;
pub mod pairing_routes;
pub mod payments;
pub mod peers;
pub mod pricing;
pub mod rooms;
pub mod routing;
pub mod sessions;
pub mod sponsor;
pub mod utils;

pub mod liquidity;

pub(crate) mod list_diagnostics;
