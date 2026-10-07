// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! Client tenants of a portfolio credential: list them, and read one of them.
//!
//! # Provisional
//!
//! **This module is written by hand against a draft of the `/v1` contract and is not part of the
//! published API description yet.** Nothing in `openapi/v1.json` or the generated client describes
//! it. When the contract is published, this file is the only place that changes: the operation, the
//! shape of [`Tenant`] and the way the selected tenant travels on a request are all decided here,
//! and callers see only the interface below.
//!
//! The draft assumes:
//!
//! - `GET /v1/portfolio/tenants`, scope `portfolio:read`, paginated like the other lists
//!   (`page`, `per_page`, answer `{ data, pagination }`);
//! - the client is selected on every data operation with one `X-HS-Tenant` request header holding
//!   the tenant's UUID, and every answer to such a request repeats it in an `X-HS-Tenant` response
//!   header;
//! - the listing does not take that header.
//!
//! # Interface
//!
//! - [`Client::list_tenants`] lists the client tenants the credential may read.
//! - [`ClientBuilder::tenant`] makes every data call of the built client read that tenant. The
//!   client then refuses any successful answer that does not name the same tenant, so data of one
//!   client is never returned as if it were another's.

use crate::client::{Operation, Scope};
use crate::error::Error;
use crate::v1::Pagination;
use crate::{ApiResponse, Client, ClientBuilder};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Request and response header that selects, and confirms, the client tenant.
const TENANT_HEADER: HeaderName = HeaderName::from_static("x-hs-tenant");

/// `GET /v1/portfolio/tenants`: List the client tenants of the credential's portfolio.
pub const LIST_TENANTS: Operation = Operation {
    id: "listPortfolioTenants",
    method: "GET",
    path: "/v1/portfolio/tenants",
    summary: "List the client tenants of the credential's portfolio",
    scopes: &["portfolio:read"],
    known_values: &[],
};

/// A client tenant of the portfolio. Text fields come from the server and are untrusted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tenant {
    /// Stable identifier (a UUID): what selects the tenant.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Short unique name, for people and scripts.
    pub slug: String,
    /// The client organisation the tenant belongs to, when it has one.
    #[serde(default)]
    pub organization: Option<TenantOrganization>,
    /// Whether this is the MSSP's own tenant rather than a client's.
    #[serde(default)]
    pub internal: bool,
    /// Whether the tenant is active.
    #[serde(default = "yes")]
    pub active: bool,
    /// `in_force`, `grace` or `inactive`. The vocabulary may grow.
    #[serde(default)]
    pub licence_status: Option<String>,
}

fn yes() -> bool {
    true
}

/// The organisation a [`Tenant`] belongs to.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TenantOrganization {
    /// Identifier of the organisation.
    pub id: String,
    /// Display name.
    pub name: String,
}

/// The answer of [`Client::list_tenants`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ListTenantsResponse {
    /// One page of tenants.
    pub data: Vec<Tenant>,
    /// Where this page sits in the whole list.
    pub pagination: Pagination,
}

/// Paging of [`Client::list_tenants`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListTenantsParams {
    /// 1-based page number.
    pub page: Option<i64>,
    /// Items per page, 1..200.
    pub per_page: Option<i64>,
}

impl ListTenantsParams {
    fn query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(page) = self.page {
            pairs.push(("page", page.to_string()));
        }
        if let Some(per_page) = self.per_page {
            pairs.push(("per_page", per_page.to_string()));
        }
        pairs
    }
}

impl Client {
    /// The client tenants this credential may read. The listing is never scoped to a tenant, even
    /// on a client built with [`ClientBuilder::tenant`].
    ///
    /// Required scope: `portfolio:read`.
    ///
    /// # Errors
    ///
    /// [`Error`] when the request cannot be sent, the API answers with an error (a credential
    /// without portfolio scope gets `403`), or the body does not match the draft.
    pub fn list_tenants(
        &self,
        params: &ListTenantsParams,
    ) -> Result<ApiResponse<ListTenantsResponse>, Error> {
        self.get_with(
            &LIST_TENANTS,
            LIST_TENANTS.path.to_owned(),
            params.query_pairs(),
            false,
        )
    }
}

impl ClientBuilder {
    /// Makes every data call of the built client read the client tenant `id`.
    ///
    /// The built client sends the selection on each request and returns an answer only when it
    /// confirms the same tenant; otherwise the call fails with [`Error::TenantMismatch`].
    ///
    /// # Errors
    ///
    /// [`Error::InvalidTenant`] when `id` is not a UUID.
    pub fn tenant(mut self, id: &str) -> Result<Self, Error> {
        if !is_uuid(id) {
            return Err(Error::InvalidTenant(id.to_owned()));
        }
        let wanted = id.to_ascii_lowercase();
        let mut headers = HeaderMap::new();
        headers.insert(
            TENANT_HEADER,
            HeaderValue::from_str(&wanted).map_err(|_| Error::InvalidTenant(id.to_owned()))?,
        );
        let check = move |answer: &HeaderMap| {
            let answered = answer
                .get(TENANT_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(|v| v.trim().to_ascii_lowercase());
            if answered.as_deref() == Some(wanted.as_str()) {
                Ok(())
            } else {
                Err(Error::TenantMismatch {
                    requested: wanted.clone(),
                    answered,
                })
            }
        };
        self.scope = Scope {
            headers,
            check: Some(Arc::new(check)),
        };
        Ok(self)
    }
}

/// Whether `text` is a UUID in the 8-4-4-4-12 form, in any case. The one check for tenant ids: the
/// tenant selection and the `X-HS-Tenant` metadata both use it.
#[must_use]
pub fn is_uuid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(g, len)| g.len() == len && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_uuids_only() {
        assert!(is_uuid("0b8f2a52-6a0e-4d5c-9d3e-1f2a3b4c5d6e"));
        assert!(is_uuid("0B8F2A52-6A0E-4D5C-9D3E-1F2A3B4C5D6E"));
        for bad in [
            "",
            "acme",
            "0b8f2a52-6a0e-4d5c-9d3e",
            "0b8f2a52-6a0e-4d5c-9d3e-1f2a3b4c5d6",
            "0b8f2a52-6a0e-4d5c-9d3e-1f2a3b4c5d6g",
            "a, b",
        ] {
            assert!(!is_uuid(bad), "{bad:?}");
        }
    }
}
