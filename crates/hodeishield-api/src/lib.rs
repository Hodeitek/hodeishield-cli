// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! Read-only client for the HodeiShield `/v1` API.
//!
//! The types, query parameters and operations in [`v1`] are generated from the vendored OpenAPI
//! document (`openapi/v1.json`) by `cargo xtask codegen`; this file is the hand-written transport they
//! run on. Every operation is a `GET`: the client has no way to change anything.
//!
//! ```no_run
//! use hodeishield_api::{Client, v1::ListVendorsParams};
//! use secrecy::SecretString;
//!
//! let client = Client::new(
//!     "https://api.hodeishield.com".parse()?,
//!     SecretString::from(std::env::var("HODEISHIELD_API_KEY")?),
//! )?;
//! let page = client.list_vendors(&ListVendorsParams::default())?;
//! for vendor in page.data.data {
//!     println!("{} {}", vendor.id, vendor.name);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod client;
mod error;
#[allow(missing_docs)]
#[path = "generated.rs"]
pub mod v1;

pub use client::{
    ApiResponse, Client, ClientBuilder, MAX_RESPONSE_BYTES, Operation, RateLimit, RequestEvent,
    ResponseMeta, encode_path_segment, is_loopback_host, read_body,
};
pub use error::{ApiError, ApiErrorBody, Error, ParseEnumError};
