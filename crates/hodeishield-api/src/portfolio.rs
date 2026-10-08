// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! Client tenants of a portfolio credential: list them, and read one of them.
//!
//! This module follows the published `/v1` portfolio contract (contract version `2026-10-16`):
//!
//! - `GET /v1/portfolio/tenants` (`listPortfolioTenants`), scope `portfolio:read`, paginated like
//!   every `/v1` list (`page`, `per_page`, `sort`, `order`; the API's default order is descending,
//!   so this client asks for ascending);
//! - the client tenant is selected on each of the data operations with one optional `X-HS-Tenant`
//!   request header holding the tenant's UUID, and every successful answer to such a request
//!   repeats the tenant it read in an `X-HS-Tenant` response header (lowercase UUID). Error
//!   answers never carry it, and the listing neither takes nor returns it;
//! - a tenant is readable when it is active and its `licence_status` is `in_force` or `grace`. The
//!   `licence_status` vocabulary is open: a value this client does not know counts as not
//!   readable.
//!
//! The version string of the API description is not compared with anything. Whether an API offers
//! portfolio access is found by asking for the listing: a `404` or `405` on that route becomes
//! [`Error::PortfolioNotOffered`].
//!
//! # Relation to the generated client
//!
//! The vendored `openapi/v1.json` does not describe these operations yet, so this file is written
//! by hand. When the vendored document is synced to the contract version above, the listing
//! operation, [`Tenant`] and the paging types come from `cargo xtask codegen` (which first has to
//! learn header parameters and the new security scheme), and this file shrinks to what is not an
//! operation: [`ClientBuilder::tenant`] and its confirmation check, which the generated code does
//! not provide.
//!
//! # Interface
//!
//! - [`Client::list_tenants`] lists the client tenants the credential may read.
//! - [`ClientBuilder::tenant`] makes every data call of the built client read that tenant. The
//!   client then refuses any successful answer that does not name the same tenant, so data of one
//!   client is never returned as if it were another's.

use crate::client::{Operation, Scope};
use crate::error::Error;
use crate::v1::{Order, Pagination};
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
    /// Short name, unique across the platform, for people and scripts.
    pub slug: String,
    /// The organisation the tenant belongs to: the MSSP's own for the tenants it holds directly.
    pub organization: TenantOrganization,
    /// Whether this is the MSSP's own internal tenant rather than a client's.
    pub internal: bool,
    /// Whether the tenant is enabled.
    pub active: bool,
    /// `in_force`, `grace` or `inactive`. The vocabulary is open: other values may appear.
    pub licence_status: String,
}

impl Tenant {
    /// Whether reading this tenant can be expected to work: it is active and its licence is in
    /// force or in its grace period. A licence status this client does not know counts as not
    /// readable, since the vocabulary is open.
    #[must_use]
    pub fn readable(&self) -> bool {
        self.active && matches!(self.licence_status.as_str(), "in_force" | "grace")
    }
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

/// What [`Client::list_tenants`] sends.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ListTenantsParams {
    /// 1-based page number.
    pub page: Option<i64>,
    /// Items per page, 1..200.
    pub per_page: Option<i64>,
    /// Sort by `name` or `slug`.
    pub sort: Option<TenantSort>,
    /// Direction. The API's default is descending.
    pub order: Option<Order>,
}

/// The fields the tenant listing can be sorted by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TenantSort {
    /// `name`
    Name,
    /// `slug`
    Slug,
}

impl TenantSort {
    /// The value as sent on the wire.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Slug => "slug",
        }
    }
}

impl ListTenantsParams {
    /// Alphabetical by name, the order a person expects.
    #[must_use]
    pub fn alphabetical(page: Option<i64>, per_page: Option<i64>) -> Self {
        Self {
            page,
            per_page,
            sort: Some(TenantSort::Name),
            order: Some(Order::Asc),
        }
    }

    fn query_pairs(&self) -> Vec<(&'static str, String)> {
        let mut pairs = Vec::new();
        if let Some(page) = self.page {
            pairs.push(("page", page.to_string()));
        }
        if let Some(per_page) = self.per_page {
            pairs.push(("per_page", per_page.to_string()));
        }
        if let Some(sort) = self.sort {
            pairs.push(("sort", sort.as_str().to_owned()));
        }
        if let Some(order) = self.order {
            pairs.push(("order", order.as_str().to_owned()));
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
    /// without portfolio scope gets `403`), or the body does not match the contract.
    /// [`Error::PortfolioNotOffered`] when the API has no such route.
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
        .map_err(|error| match error {
            Error::Api(api) if matches!(api.status, 404 | 405) => {
                Error::PortfolioNotOffered { status: api.status }
            }
            other => other,
        })
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
            // Header names compare case-insensitively (the map does it); the answer must carry
            // exactly one value, the lowercase UUID of the tenant that was read.
            let mut values = answer.get_all(TENANT_HEADER).iter();
            let answered = match (values.next(), values.next()) {
                (Some(value), None) => value.to_str().ok().map(str::to_owned),
                _ => None,
            };
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

    fn tenant(active: bool, licence: &str) -> Tenant {
        Tenant {
            id: "0b8f2a52-6a0e-4d5c-9d3e-1f2a3b4c5d6e".to_owned(),
            name: "Acme".to_owned(),
            slug: "acme".to_owned(),
            organization: TenantOrganization {
                id: "o".to_owned(),
                name: "Acme Group".to_owned(),
            },
            internal: false,
            active,
            licence_status: licence.to_owned(),
        }
    }

    #[test]
    fn a_tenant_is_readable_only_when_active_with_a_known_good_licence() {
        assert!(tenant(true, "in_force").readable());
        assert!(tenant(true, "grace").readable());
        assert!(!tenant(true, "inactive").readable());
        assert!(!tenant(false, "in_force").readable());
        assert!(!tenant(false, "grace").readable());
        // The vocabulary is open: what is not known is not assumed readable.
        assert!(!tenant(true, "suspended_soon").readable());
        assert!(!tenant(true, "").readable());
        assert!(!tenant(true, "IN_FORCE").readable());
    }

    #[test]
    fn the_listing_asks_for_ascending_names_when_told_to() {
        let pairs = ListTenantsParams::alphabetical(Some(2), Some(200)).query_pairs();
        assert_eq!(
            pairs,
            vec![
                ("page", "2".to_owned()),
                ("per_page", "200".to_owned()),
                ("sort", "name".to_owned()),
                ("order", "asc".to_owned()),
            ]
        );
        assert!(ListTenantsParams::default().query_pairs().is_empty());
    }
}
