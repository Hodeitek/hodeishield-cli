// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! Repository tasks.
//!
//! `cargo xtask codegen` generates `crates/hodeishield-api/src/generated.rs` from the vendored
//! OpenAPI document in `openapi/v1.json`; `cargo xtask codegen --check` fails when the committed file
//! is not what the document generates, or when the document is not the one recorded below.
//!
//! The generator is deliberately small and only understands the subset of OpenAPI 3.1 / JSON Schema
//! 2020-12 that `/v1` uses. Anything outside that subset is an error, never a guess: a new construct in
//! the document has to be taught here before the client can be regenerated.
//!
//! Rules it applies:
//! - Response objects become structs that ignore unknown fields, so a newer `/v1` (which only adds)
//!   does not break an older client.
//! - Enums in responses stay `String`: the contract says vocabularies may grow.
//! - Enums in query parameters become Rust enums: the client only sends what the document lists.
//! - Two schemas with the same shape become one type; two different shapes wanting the same name
//!   abort generation instead of being silently renamed.

use clap::CommandFactory;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

const SPEC: &str = "openapi/v1.json";
const OUT: &str = "crates/hodeishield-api/src/generated.rs";
/// SHA-256 of `openapi/v1.json`. Updating the document means updating this and `openapi/README.md`.
const EXPECTED_SHA256: &str = "103e86f38f7b3eff45a0f764c8142b4bdd2e8d576385b1b4ccf588cbf0518fb3";

/// Type names that the default naming rules would get wrong, keyed by the schema's location.
const RENAMES: &[(&str, &str)] = &[
    ("#/components/schemas/Error", "ErrorEnvelope"),
    ("#/components/schemas/Error/properties/error", "ErrorBody"),
];

type Result<T> = std::result::Result<T, String>;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("codegen") => {
            let check = match args.get(1).map(String::as_str) {
                None => Ok(false),
                Some("--check") => Ok(true),
                Some(other) => Err(format!("unknown argument `{other}`")),
            };
            check.and_then(codegen)
        }
        Some("man") => match args.get(1) {
            Some(out_dir) => man(out_dir),
            None => Err("usage: cargo xtask man <out-dir>".to_owned()),
        },
        _ => Err("usage: cargo xtask codegen [--check] | cargo xtask man <out-dir>".to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("xtask: {message}");
            ExitCode::FAILURE
        }
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn codegen(check: bool) -> Result<()> {
    let root = root();
    let bytes = std::fs::read(root.join(SPEC)).map_err(|e| format!("reading {SPEC}: {e}"))?;
    let digest = hex(&Sha256::digest(&bytes));
    if digest != EXPECTED_SHA256 {
        return Err(format!(
            "{SPEC} has SHA-256 {digest}, expected {EXPECTED_SHA256}. \
             If the document was updated on purpose, record the new hash in xtask/src/main.rs \
             and openapi/README.md."
        ));
    }
    let spec: Value = serde_json::from_slice(&bytes).map_err(|e| format!("parsing {SPEC}: {e}"))?;
    let source = Generator::new(&spec).run()?;
    let formatted = rustfmt(&source)?;
    let out = root.join(OUT);
    if check {
        let current = std::fs::read_to_string(&out).map_err(|e| format!("reading {OUT}: {e}"))?;
        if current != formatted {
            return Err(format!(
                "{OUT} is not what {SPEC} generates. Run `cargo xtask codegen` and commit the result."
            ));
        }
        eprintln!("xtask: {OUT} is up to date with {SPEC}");
    } else {
        std::fs::write(&out, formatted).map_err(|e| format!("writing {OUT}: {e}"))?;
        eprintln!("xtask: wrote {OUT}");
    }
    Ok(())
}

fn man(out_dir: &str) -> Result<()> {
    std::fs::create_dir_all(out_dir).map_err(|e| format!("creating {out_dir}: {e}"))?;
    let cmd = hodeishield_cli::cli::Cli::command();
    clap_mangen::generate_to(cmd, out_dir).map_err(|e| format!("generating man pages: {e}"))?;
    eprintln!("xtask: generated man pages in {out_dir}");
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

fn rustfmt(source: &str) -> Result<String> {
    let mut child = Command::new("rustfmt")
        .args(["--edition", "2024", "--emit", "stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("running rustfmt: {e}"))?;
    child
        .stdin
        .take()
        .ok_or("rustfmt stdin unavailable")?
        .write_all(source.as_bytes())
        .map_err(|e| format!("writing to rustfmt: {e}"))?;
    let output = child
        .wait_with_output()
        .map_err(|e| format!("waiting for rustfmt: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "rustfmt rejected the generated code:\n{}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("rustfmt output: {e}"))
}

// ---------------------------------------------------------------------------------------------
// Model

struct Field {
    json_name: String,
    rust_name: String,
    ty: String,
    optional: bool,
    doc: Option<String>,
}

struct StructDef {
    name: String,
    doc: Option<String>,
    fields: Vec<Field>,
}

struct EnumDef {
    name: String,
    values: Vec<String>,
}

struct Param {
    json_name: String,
    rust_name: String,
    /// Rust type of the value, without the `Option`.
    ty: String,
    required: bool,
    is_enum: bool,
    /// The values `x-hs-known-values` lists, in document order; empty without the extension.
    known_values: Vec<String>,
    doc: Option<String>,
}

struct OperationDef {
    id: String,
    path: String,
    summary: String,
    description: Option<String>,
    scopes: Vec<String>,
    path_params: Vec<Param>,
    query_params: Vec<Param>,
    response: String,
}

struct Generator<'a> {
    spec: &'a Value,
    structs: Vec<StructDef>,
    /// Canonical JSON of a schema → the type generated for it.
    by_shape: BTreeMap<String, String>,
    /// Type name → canonical JSON of the schema it was generated for.
    names: BTreeMap<String, String>,
    enums: Vec<EnumDef>,
    operations: Vec<OperationDef>,
}

impl<'a> Generator<'a> {
    fn new(spec: &'a Value) -> Self {
        Self {
            spec,
            structs: Vec::new(),
            by_shape: BTreeMap::new(),
            names: BTreeMap::new(),
            enums: Vec::new(),
            operations: Vec::new(),
        }
    }

    fn run(mut self) -> Result<String> {
        let spec = self.spec;
        let version = spec
            .pointer("/info/version")
            .and_then(Value::as_str)
            .ok_or("info.version missing")?
            .to_owned();
        let server = spec
            .pointer("/servers/0/url")
            .and_then(Value::as_str)
            .ok_or("servers[0].url missing")?
            .to_owned();

        let schemas = spec
            .pointer("/components/schemas")
            .and_then(Value::as_object)
            .ok_or("components.schemas missing")?;
        for (name, schema) in schemas {
            let location = format!("#/components/schemas/{name}");
            let hint = rename(&location).unwrap_or(name).to_owned();
            self.rust_type(schema, &hint, &location)?;
        }

        let enum_names = self.param_enum_names()?;
        let paths = spec
            .get("paths")
            .and_then(Value::as_object)
            .ok_or("paths missing")?;
        for (path, item) in paths {
            let item = item.as_object().ok_or("path item is not an object")?;
            for (method, operation) in item {
                if method != "get" {
                    return Err(format!(
                        "{method} {path}: /v1 is read-only and this client only generates GET"
                    ));
                }
                self.operation(path, operation, &enum_names)?;
            }
        }
        Ok(self.render(&version, &server))
    }

    /// Names the enum of every enumerated query parameter. A parameter whose values are the same in
    /// every operation shares one enum named after it (`order` → `Order`); otherwise the enum is
    /// prefixed with the resource (`sort` → `VendorSort`, `AlertSort`, …).
    fn param_enum_names(&mut self) -> Result<BTreeMap<(String, String), String>> {
        let mut value_sets: BTreeMap<String, BTreeSet<Vec<String>>> = BTreeMap::new();
        let mut occurrences = Vec::new();
        for (_, operation) in self.operations_iter()? {
            let id = operation_id(operation)?;
            for param in operation
                .get("parameters")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let name = param
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if let Some(values) = param.pointer("/schema/enum").and_then(Value::as_array) {
                    let values: Vec<String> = values
                        .iter()
                        .map(|v| v.as_str().map(str::to_owned).ok_or("non-string enum value"))
                        .collect::<std::result::Result<_, _>>()?;
                    value_sets
                        .entry(name.to_owned())
                        .or_default()
                        .insert(values.clone());
                    occurrences.push((id.to_owned(), name.to_owned(), values));
                }
            }
        }
        // A parameter with the same name but no enum in some operation still counts as "not shared".
        let mut plain: BTreeSet<String> = BTreeSet::new();
        for (_, operation) in self.operations_iter()? {
            for param in operation
                .get("parameters")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if param.pointer("/schema/enum").is_none()
                    && let Some(name) = param.get("name").and_then(Value::as_str)
                {
                    plain.insert(name.to_owned());
                }
            }
        }
        let mut names = BTreeMap::new();
        let mut defined: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for (id, param, values) in occurrences {
            let shared =
                value_sets.get(&param).is_some_and(|s| s.len() == 1) && !plain.contains(&param);
            let name = if shared {
                pascal(&param)
            } else {
                format!("{}{}", resource_name(&id), pascal(&param))
            };
            match defined.get(&name) {
                Some(existing) if *existing != values => {
                    return Err(format!("enum {name} would have two different value sets"));
                }
                Some(_) => {}
                None => {
                    defined.insert(name.clone(), values.clone());
                    self.enums.push(EnumDef {
                        name: name.clone(),
                        values,
                    });
                }
            }
            names.insert((id, param), name);
        }
        Ok(names)
    }

    fn operations_iter(&self) -> Result<Vec<(String, &'a Value)>> {
        let spec: &'a Value = self.spec;
        let paths = spec
            .get("paths")
            .and_then(Value::as_object)
            .ok_or("paths missing")?;
        Ok(paths
            .iter()
            .flat_map(|(path, item)| {
                item.as_object()
                    .into_iter()
                    .flatten()
                    .map(move |(_, op)| (path.clone(), op))
            })
            .collect())
    }

    fn operation(
        &mut self,
        path: &str,
        operation: &Value,
        enum_names: &BTreeMap<(String, String), String>,
    ) -> Result<()> {
        let id = operation_id(operation)?.to_owned();
        let summary = operation
            .get("summary")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("{id}: summary missing"))?
            .to_owned();
        let description = operation
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let scope = operation
            .get("x-hs-scope")
            .ok_or_else(|| format!("{id}: x-hs-scope missing"))?;
        let scopes = if let Some(list) = scope.get("scopes").and_then(Value::as_array) {
            list.iter()
                .map(|s| s.as_str().map(str::to_owned).ok_or("non-string scope"))
                .collect::<std::result::Result<Vec<_>, _>>()?
        } else if let Some(template) = scope.get("template").and_then(Value::as_str) {
            vec![template.to_owned()]
        } else {
            return Err(format!("{id}: x-hs-scope has neither scopes nor template"));
        };

        let mut path_params = Vec::new();
        let mut query_params = Vec::new();
        for param in operation
            .get("parameters")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = param
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("{id}: parameter without name"))?;
            let location = param.get("in").and_then(Value::as_str).unwrap_or_default();
            let required = param
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let schema = param
                .get("schema")
                .ok_or_else(|| format!("{id}.{name}: schema missing"))?;
            let key = (id.clone(), name.to_owned());
            let (ty, is_enum) = if let Some(enum_name) = enum_names.get(&key) {
                (enum_name.clone(), true)
            } else {
                (
                    scalar_type(schema)
                        .ok_or_else(|| format!("{id}.{name}: unsupported parameter schema"))?
                        .to_owned(),
                    false,
                )
            };
            let param = Param {
                json_name: name.to_owned(),
                rust_name: snake(name),
                ty,
                required,
                is_enum,
                known_values: known_values(&id, name, param)?,
                doc: param
                    .get("description")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
            };
            match location {
                "path" => path_params.push(param),
                "query" => query_params.push(param),
                other => {
                    return Err(format!(
                        "{id}.{name}: parameters in `{other}` are not supported"
                    ));
                }
            }
        }

        let schema = operation
            .pointer("/responses/200/content/application~1json/schema")
            .ok_or_else(|| format!("{id}: no JSON 200 response"))?;
        let response_name = format!("{}Response", pascal(&id));
        let (response, nullable) =
            self.rust_type(schema, &response_name, &format!("{id}/responses/200"))?;
        if nullable {
            return Err(format!("{id}: a nullable 200 body is not supported"));
        }
        self.operations.push(OperationDef {
            id,
            path: path.to_owned(),
            summary,
            description,
            scopes,
            path_params,
            query_params,
            response,
        });
        Ok(())
    }

    /// The Rust type for `schema`, and whether it is nullable. Objects with properties become a
    /// struct named `hint` (or the struct already generated for the same shape).
    fn rust_type(&mut self, schema: &Value, hint: &str, location: &str) -> Result<(String, bool)> {
        if let Some(reference) = schema.get("$ref").and_then(Value::as_str) {
            let name = reference
                .strip_prefix("#/components/schemas/")
                .ok_or_else(|| format!("{location}: unsupported $ref {reference}"))?;
            let target = rename(reference).unwrap_or(name);
            return Ok((target.to_owned(), false));
        }
        if let Some(variants) = schema.get("anyOf").and_then(Value::as_array) {
            let non_null: Vec<&Value> = variants
                .iter()
                .filter(|v| v.get("type").and_then(Value::as_str) != Some("null"))
                .collect();
            if non_null.len() != 1 || variants.len() != 2 {
                return Err(format!("{location}: only `anyOf: [T, null]` is supported"));
            }
            let (ty, _) = self.rust_type(non_null[0], hint, location)?;
            return Ok((ty, true));
        }
        let (kind, nullable) = match schema.get("type") {
            Some(Value::String(kind)) => (kind.as_str(), false),
            Some(Value::Array(kinds)) => {
                let non_null: Vec<&str> = kinds
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|k| *k != "null")
                    .collect();
                if non_null.len() != 1 || kinds.len() != 2 {
                    return Err(format!(
                        "{location}: only `type: [T, \"null\"]` is supported"
                    ));
                }
                (non_null[0], true)
            }
            _ => return Err(format!("{location}: schema without a type")),
        };
        let ty = match kind {
            "string" => "String".to_owned(),
            "integer" => "i64".to_owned(),
            "number" => "f64".to_owned(),
            "boolean" => "bool".to_owned(),
            "array" => {
                let items = schema
                    .get("items")
                    .ok_or_else(|| format!("{location}: array without items"))?;
                let (inner, inner_nullable) =
                    self.rust_type(items, hint, &format!("{location}/items"))?;
                if inner_nullable {
                    format!("Vec<Option<{inner}>>")
                } else {
                    format!("Vec<{inner}>")
                }
            }
            "object" => self.object_type(schema, hint, location)?,
            other => return Err(format!("{location}: unsupported type `{other}`")),
        };
        Ok((ty, nullable))
    }

    fn object_type(&mut self, schema: &Value, hint: &str, location: &str) -> Result<String> {
        let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
            return match schema.get("additionalProperties") {
                Some(additional @ Value::Object(_)) => {
                    let (inner, _) = self.rust_type(
                        additional,
                        &format!("{hint}Value"),
                        &format!("{location}/additionalProperties"),
                    )?;
                    Ok(format!("std::collections::BTreeMap<String, {inner}>"))
                }
                _ => Ok("serde_json::Map<String, serde_json::Value>".to_owned()),
            };
        };
        let shape = canonical(schema);
        if let Some(existing) = self.by_shape.get(&shape) {
            return Ok(existing.clone());
        }
        let name = rename(location).unwrap_or(hint).to_owned();
        if let Some(other) = self.names.get(&name)
            && *other != shape
        {
            return Err(format!(
                "{location}: two different schemas want the name `{name}`; add an entry to RENAMES"
            ));
        }
        self.names.insert(name.clone(), shape.clone());
        self.by_shape.insert(shape, name.clone());

        let required: BTreeSet<&str> = schema
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let mut fields = Vec::new();
        for (property, property_schema) in properties {
            let child_location = format!("{location}/properties/{property}");
            let child_hint = if property == "data" {
                // `data` is the resource itself: name it after the resource, not after the envelope.
                hint.strip_suffix("Response")
                    .map(resource_name_from_pascal)
                    .unwrap_or_else(|| pascal(property))
            } else {
                pascal(property)
            };
            let (ty, nullable) = self.rust_type(property_schema, &child_hint, &child_location)?;
            let mut doc = property_schema
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if let Some(values) = property_schema.get("enum").and_then(Value::as_array) {
                let listed: Vec<String> = values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(|v| format!("`{v}`"))
                    .collect();
                let note = format!(
                    "Documented values: {}. Treat any other value as valid: the vocabulary may grow.",
                    listed.join(", ")
                );
                doc = Some(match doc {
                    Some(d) => format!("{d}\n\n{note}"),
                    None => note,
                });
            }
            fields.push(Field {
                json_name: property.clone(),
                rust_name: snake(property),
                ty,
                optional: nullable || !required.contains(property.as_str()),
                doc,
            });
        }
        self.structs.push(StructDef {
            name: name.clone(),
            doc: schema
                .get("description")
                .and_then(Value::as_str)
                .map(str::to_owned),
            fields,
        });
        Ok(name)
    }

    // -----------------------------------------------------------------------------------------
    // Rendering

    fn render(&self, version: &str, server: &str) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "// SPDX-License-Identifier: Apache-2.0\n\
             // Copyright 2026 Hodeitek S.L.\n\
             // @generated by `cargo xtask codegen` from openapi/v1.json. Do not edit by hand.\n\
             //\n\
             // Types, query parameters and operations of the HodeiShield `/v1` API.\n\n\
             #![allow(clippy::doc_markdown, clippy::too_many_lines, clippy::struct_excessive_bools)]\n\n\
             use serde::{{Deserialize, Serialize}};\n\n\
             /// `info.version` of the OpenAPI document this client was generated from.\n\
             pub const OPENAPI_VERSION: &str = {version:?};\n\n\
             /// The server the OpenAPI document declares.\n\
             pub const DEFAULT_SERVER: &str = {server:?};\n"
        );

        for def in &self.structs {
            render_doc(&mut out, def.doc.as_deref(), "");
            out.push_str("#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]\n");
            let _ = writeln!(out, "pub struct {} {{", def.name);
            for field in &def.fields {
                render_doc(&mut out, field.doc.as_deref(), "    ");
                if field.rust_name.trim_start_matches("r#") != field.json_name {
                    let _ = writeln!(out, "    #[serde(rename = {:?})]", field.json_name);
                }
                if field.optional {
                    out.push_str("    #[serde(default)]\n");
                    let _ = writeln!(out, "    pub {}: Option<{}>,", field.rust_name, field.ty);
                } else {
                    let _ = writeln!(out, "    pub {}: {},", field.rust_name, field.ty);
                }
            }
            out.push_str("}\n\n");
        }

        for def in &self.enums {
            let _ = writeln!(
                out,
                "/// Accepted values of a query parameter.\n\
                 #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]\n\
                 pub enum {} {{",
                def.name
            );
            for value in &def.values {
                let _ = writeln!(out, "    /// `{value}`\n    {},", pascal(value));
            }
            let _ = writeln!(out, "}}\n\nimpl {} {{", def.name);
            let listed: Vec<String> = def.values.iter().map(|v| format!("{v:?}")).collect();
            let _ = writeln!(
                out,
                "    /// Every accepted value, as sent on the wire.\n    pub const VALUES: &'static [&'static str] = &[{}];\n",
                listed.join(", ")
            );
            out.push_str("    /// The value as sent on the wire.\n    #[must_use]\n    pub fn as_str(self) -> &'static str {\n        match self {\n");
            for value in &def.values {
                let _ = writeln!(out, "            Self::{} => {value:?},", pascal(value));
            }
            out.push_str("        }\n    }\n}\n\n");
            let _ = writeln!(
                out,
                "impl std::fmt::Display for {name} {{\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {{\n        f.write_str(self.as_str())\n    }}\n}}\n\n\
                 impl std::str::FromStr for {name} {{\n    type Err = crate::ParseEnumError;\n\n    fn from_str(value: &str) -> Result<Self, Self::Err> {{\n        match value {{",
                name = def.name
            );
            for value in &def.values {
                let _ = writeln!(out, "            {value:?} => Ok(Self::{}),", pascal(value));
            }
            out.push_str("            _ => Err(crate::ParseEnumError::new(value, Self::VALUES)),\n        }\n    }\n}\n\n");
        }

        for op in &self.operations {
            if op.query_params.is_empty() {
                continue;
            }
            let name = format!("{}Params", pascal(&op.id));
            let has_required = op.query_params.iter().any(|p| p.required);
            let _ = writeln!(out, "/// Query parameters of `{}`.", op.id);
            if has_required {
                out.push_str("#[derive(Debug, Clone, PartialEq)]\n");
            } else {
                out.push_str("#[derive(Debug, Clone, Default, PartialEq)]\n");
            }
            let _ = writeln!(out, "pub struct {name} {{");
            for param in &op.query_params {
                render_doc(&mut out, param.doc.as_deref(), "    ");
                if param.required {
                    let _ = writeln!(out, "    pub {}: {},", param.rust_name, param.ty);
                } else {
                    let _ = writeln!(out, "    pub {}: Option<{}>,", param.rust_name, param.ty);
                }
            }
            let _ = writeln!(out, "}}\n\nimpl {name} {{");
            if has_required {
                let args: Vec<String> = op
                    .query_params
                    .iter()
                    .filter(|p| p.required)
                    .map(|p| format!("{}: impl Into<{}>", p.rust_name, p.ty))
                    .collect();
                let inits: Vec<String> = op
                    .query_params
                    .iter()
                    .map(|p| {
                        if p.required {
                            format!("{}: {}.into()", p.rust_name, p.rust_name)
                        } else {
                            format!("{}: None", p.rust_name)
                        }
                    })
                    .collect();
                let _ = writeln!(
                    out,
                    "    /// Parameters with every optional one unset.\n    #[must_use]\n    pub fn new({}) -> Self {{\n        Self {{ {} }}\n    }}\n",
                    args.join(", "),
                    inits.join(", ")
                );
            }
            out.push_str("    /// The query string, in document order, without the parameters that are unset.\n    #[must_use]\n    pub fn query_pairs(&self) -> Vec<(&'static str, String)> {\n        let mut pairs = Vec::new();\n");
            for param in &op.query_params {
                let value = if param.is_enum {
                    "value.as_str().to_owned()"
                } else if param.ty == "String" {
                    "value.clone()"
                } else {
                    "value.to_string()"
                };
                if param.required {
                    let expr = value.replace("value", &format!("self.{}", param.rust_name));
                    let _ = writeln!(out, "        pairs.push(({:?}, {expr}));", param.json_name);
                } else {
                    let _ = writeln!(
                        out,
                        "        if let Some(value) = &self.{} {{\n            pairs.push(({:?}, {value}));\n        }}",
                        param.rust_name, param.json_name
                    );
                }
            }
            out.push_str("        pairs\n    }\n}\n\n");
        }

        out.push_str("/// Every `/v1` operation, as the OpenAPI document describes it.\npub mod operations {\n    use crate::Operation;\n\n");
        for op in &self.operations {
            let scopes: Vec<String> = op.scopes.iter().map(|s| format!("{s:?}")).collect();
            let known: Vec<String> = op
                .query_params
                .iter()
                .filter(|p| !p.known_values.is_empty())
                .map(|p| {
                    let values: Vec<String> =
                        p.known_values.iter().map(|v| format!("{v:?}")).collect();
                    format!("({:?}, &[{}])", p.json_name, values.join(", "))
                })
                .collect();
            let _ = writeln!(
                out,
                "    /// `GET {}`: {}.\n    pub const {}: Operation = Operation {{ id: {:?}, method: \"GET\", path: {:?}, summary: {:?}, scopes: &[{}], known_values: &[{}] }};\n",
                op.path,
                op.summary,
                screaming(&op.id),
                op.id,
                op.path,
                op.summary,
                scopes.join(", "),
                known.join(", ")
            );
        }
        let all: Vec<String> = self.operations.iter().map(|op| screaming(&op.id)).collect();
        let _ = writeln!(
            out,
            "    /// All operations, in document order.\n    pub const ALL: &[Operation] = &[{}];\n}}\n",
            all.join(", ")
        );

        out.push_str("impl crate::Client {\n");
        for op in &self.operations {
            let mut doc = format!("{}.", op.summary);
            if let Some(description) = &op.description {
                let _ = write!(doc, "\n\n{description}");
            }
            render_doc(&mut out, Some(&doc), "    ");
            out.push_str("    ///\n    /// # Errors\n    ///\n    /// [`crate::Error`] when the request cannot be sent, the API answers with an error, or the\n    /// body does not match the document.\n");
            let mut args = vec!["&self".to_owned()];
            for param in &op.path_params {
                args.push(format!("{}: &str", param.rust_name));
            }
            if !op.query_params.is_empty() {
                args.push(format!("params: &{}Params", pascal(&op.id)));
            }
            let mut path_expr = op.path.clone();
            let mut format_args = Vec::new();
            for param in &op.path_params {
                path_expr = path_expr.replace(&format!("{{{}}}", param.json_name), "{}");
                format_args.push(format!("crate::encode_path_segment({})?", param.rust_name));
            }
            let path_value = if format_args.is_empty() {
                format!("{path_expr:?}.to_owned()")
            } else {
                format!("format!({path_expr:?}, {})", format_args.join(", "))
            };
            let query = if op.query_params.is_empty() {
                "Vec::new()"
            } else {
                "params.query_pairs()"
            };
            let _ = writeln!(
                out,
                "    pub fn {}({}) -> Result<crate::ApiResponse<{}>, crate::Error> {{\n        self.get(&operations::{}, {path_value}, {query})\n    }}\n",
                snake(&op.id),
                args.join(", "),
                op.response,
                screaming(&op.id),
            );
        }
        out.push_str("}\n");
        out
    }
}

fn render_doc(out: &mut String, doc: Option<&str>, indent: &str) {
    let Some(doc) = doc else { return };
    for line in doc.trim().lines() {
        if line.trim().is_empty() {
            let _ = writeln!(out, "{indent}///");
        } else {
            let _ = writeln!(out, "{indent}/// {}", line.trim_end());
        }
    }
}

/// The vocabulary `x-hs-known-values` publishes for a query parameter, in document order. The
/// extension is optional; when present it must be an array of strings, anything else is an error.
fn known_values(operation: &str, name: &str, param: &Value) -> Result<Vec<String>> {
    let Some(list) = param.get("x-hs-known-values") else {
        return Ok(Vec::new());
    };
    list.as_array()
        .and_then(|items| {
            items
                .iter()
                .map(|v| v.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| format!("{operation}.{name}: x-hs-known-values must be an array of strings"))
}

fn operation_id(operation: &Value) -> Result<&str> {
    operation
        .get("operationId")
        .and_then(Value::as_str)
        .ok_or_else(|| "operation without operationId".to_owned())
}

fn rename(location: &str) -> Option<&'static str> {
    RENAMES
        .iter()
        .find(|(from, _)| *from == location)
        .map(|(_, to)| *to)
}

fn scalar_type(schema: &Value) -> Option<&'static str> {
    match schema.get("type").and_then(Value::as_str)? {
        "string" => Some("String"),
        "integer" => Some("i64"),
        "number" => Some("f64"),
        "boolean" => Some("bool"),
        _ => None,
    }
}

/// Canonical form of a schema for shape comparison: keys sorted at every level.
fn canonical(value: &Value) -> String {
    fn sort(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let sorted: BTreeMap<&String, Value> =
                    map.iter().map(|(k, v)| (k, sort(v))).collect();
                let mut out = Map::new();
                for (k, v) in sorted {
                    out.insert(k.clone(), v);
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(items.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    sort(value).to_string()
}

/// `listVendors` → `Vendor`, `getFrameworkPosture` → `FrameworkPosture`, `listEvidence` → `Evidence`.
fn resource_name(operation_id: &str) -> String {
    resource_name_from_pascal(&pascal(operation_id))
}

fn resource_name_from_pascal(name: &str) -> String {
    let noun = name
        .strip_prefix("List")
        .or_else(|| name.strip_prefix("Get"))
        .unwrap_or(name);
    match noun.strip_suffix('s') {
        Some(singular) if !noun.ends_with("ss") => singular.to_owned(),
        _ => noun.to_owned(),
    }
}

fn words(input: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut previous_lower = false;
    for c in input.chars() {
        if c == '_' || c == '-' || c == ' ' || c == '.' {
            if !current.is_empty() {
                words.push(std::mem::take(&mut current));
            }
            previous_lower = false;
        } else if c.is_uppercase() && previous_lower {
            words.push(std::mem::take(&mut current));
            current.push(c);
            previous_lower = false;
        } else {
            current.push(c);
            previous_lower = c.is_lowercase() || c.is_ascii_digit();
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn pascal(input: &str) -> String {
    words(input)
        .iter()
        .map(|w| {
            let mut chars = w.chars();
            chars.next().map_or_else(String::new, |first| {
                first
                    .to_uppercase()
                    .chain(chars.flat_map(char::to_lowercase))
                    .collect()
            })
        })
        .collect()
}

const KEYWORDS: &[&str] = &[
    "as", "async", "await", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
    "false", "fn", "for", "gen", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut",
    "pub", "ref", "return", "self", "static", "struct", "super", "trait", "true", "type", "unsafe",
    "use", "where", "while", "yield",
];

fn snake(input: &str) -> String {
    let name = words(input)
        .iter()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join("_");
    if KEYWORDS.contains(&name.as_str()) {
        format!("r#{name}")
    } else {
        name
    }
}

fn screaming(input: &str) -> String {
    snake(input).to_uppercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        assert_eq!(pascal("listVendors"), "ListVendors");
        assert_eq!(snake("listComplianceControls"), "list_compliance_controls");
        assert_eq!(snake("type"), "r#type");
        assert_eq!(screaming("getFrameworkPosture"), "GET_FRAMEWORK_POSTURE");
        assert_eq!(pascal("created_at"), "CreatedAt");
        assert_eq!(resource_name("listVendors"), "Vendor");
        assert_eq!(resource_name("listEvidence"), "Evidence");
        assert_eq!(resource_name("getFrameworkPosture"), "FrameworkPosture");
        assert_eq!(resource_name("listComplianceControls"), "ComplianceControl");
    }

    /// A minimal document with one operation whose `severity` query parameter carries `extension`
    /// (when given) and whose `page` parameter never does.
    fn document(extension: Option<Value>) -> Value {
        let mut severity = serde_json::json!({
            "name": "severity", "in": "query", "schema": {"type": "string"}
        });
        if let Some(extension) = extension {
            severity["x-hs-known-values"] = extension;
        }
        serde_json::json!({
            "info": {"version": "test"},
            "servers": [{"url": "https://api.example.test"}],
            "components": {"schemas": {}},
            "paths": {"/v1/things": {"get": {
                "operationId": "listThings",
                "summary": "List things",
                "x-hs-scope": {"scopes": ["things:read"]},
                "parameters": [severity, {"name": "page", "in": "query", "schema": {"type": "string"}}],
                "responses": {"200": {"content": {"application/json": {"schema": {
                    "type": "object",
                    "properties": {"ok": {"type": "boolean"}},
                    "required": ["ok"]
                }}}}}
            }}}
        })
    }

    fn generate(extension: Option<Value>) -> Result<String> {
        let spec = document(extension);
        Generator::new(&spec)
            .run()
            .map(|out| out.split_whitespace().collect::<Vec<_>>().join(" "))
    }

    #[test]
    fn known_values_are_emitted_in_document_order() {
        let out =
            generate(Some(serde_json::json!(["critical", "high", "info"]))).expect("generates");
        assert!(
            out.contains(r#"known_values: &[("severity", &["critical", "high", "info"])]"#),
            "{out}"
        );
    }

    #[test]
    fn a_parameter_without_the_extension_has_no_known_values() {
        let out = generate(None).expect("generates");
        assert!(out.contains("known_values: &[]"), "{out}");
        assert!(!out.contains("known_values: &[("), "{out}");
    }

    #[test]
    fn an_empty_vocabulary_is_the_same_as_none() {
        let out = generate(Some(serde_json::json!([]))).expect("generates");
        assert!(out.contains("known_values: &[]"), "{out}");
    }

    #[test]
    fn a_malformed_extension_is_a_generator_error() {
        for bad in [
            serde_json::json!("critical"),
            serde_json::json!({"critical": true}),
            serde_json::json!(["critical", 3]),
            serde_json::json!(null),
        ] {
            let err = generate(Some(bad.clone())).expect_err("malformed");
            assert_eq!(
                err, "listThings.severity: x-hs-known-values must be an array of strings",
                "{bad}"
            );
        }
    }
}
