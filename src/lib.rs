// SPDX-FileCopyrightText: OpenTalk GmbH <mail@opentalk.eu>
//
// SPDX-License-Identifier: EUPL-1.2

//! This library provides middlewares to authorize internal services

use std::fmt::Debug;

use serde::{Deserialize, Serialize};

#[cfg(any(feature = "actix", feature = "axum"))]
pub mod service;

mod credentials;

pub use credentials::{Credentials, JWT_EXPIRY};

/// The identifier of an API key
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ApiKeyId(pub String);

impl<T: Into<String>> From<T> for ApiKeyId {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

/// A secret API key
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ApiKey(pub String);

impl<T: Into<String>> From<T> for ApiKey {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Key").field(&"[redacted]").finish()
    }
}
