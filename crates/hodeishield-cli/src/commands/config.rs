// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Hodeitek S.L.

//! `config`: read and change the configuration file. It never holds a credential.

use super::Context;
use crate::cli::ConfigCommand;
use crate::config::{self, DEFAULT_PROFILE};
use crate::failure::{Failure, Result};
use crate::output::print_json;
use serde_json::json;
use std::io::Write;

pub fn run(ctx: &Context, command: ConfigCommand, out: &mut dyn Write) -> Result<()> {
    let path = config::path()?;
    match command {
        ConfigCommand::Path => {
            writeln!(out, "{}", path.display())?;
            Ok(())
        }
        ConfigCommand::Show => {
            let settings = ctx.settings()?;
            let update_check = config::load(&path)?.update_check.unwrap_or(true);
            let value = json!({
                "config_file": settings.config_path.display().to_string(),
                "profile": settings.profile,
                "api_url": settings.api_url.as_str(),
                "app_url": settings.app_url.as_str(),
                "oauth_client_id": settings.oauth_client_id,
                "oauth_scopes": settings.oauth_scopes,
                "update_check": update_check,
            });
            if ctx.json {
                return Ok(print_json(out, &value)?);
            }
            let scopes = settings
                .oauth_scopes
                .map_or_else(|| "(what the commands need)".to_owned(), |s| s.join(" "));
            writeln!(out, "config_file      {}", settings.config_path.display())?;
            writeln!(out, "profile          {}", settings.profile)?;
            writeln!(out, "api_url          {}", settings.api_url)?;
            writeln!(out, "app_url          {}", settings.app_url)?;
            writeln!(out, "oauth_client_id  {}", settings.oauth_client_id)?;
            writeln!(out, "oauth_scopes     {scopes}")?;
            writeln!(out, "update_check     {update_check}")?;
            Ok(())
        }
        ConfigCommand::Set { key, value } if key == config::UPDATE_CHECK => {
            edit_global(&path, |file| file.set_update_check(&value))
        }
        ConfigCommand::Unset { key } if key == config::UPDATE_CHECK => edit_global(&path, |file| {
            file.update_check = None;
            Ok(())
        }),
        ConfigCommand::Set { key, value } => edit(ctx, &path, |profile| profile.set(&key, &value)),
        ConfigCommand::Unset { key } => edit(ctx, &path, |profile| profile.unset(&key)),
        ConfigCommand::Use { name } => {
            let mut file = config::load(&path)?;
            if name != DEFAULT_PROFILE && !file.profiles.contains_key(&name) {
                return Err(
                    Failure::general(format!("Profile `{name}` is not defined.")).hint(format!(
                        "Create it first: `hodeishield config set --profile {name} api_url <URL>`."
                    )),
                );
            }
            file.default_profile = Some(name.clone());
            config::save(&path, &file)?;
            eprintln!("Default profile is now `{name}`.");
            Ok(())
        }
    }
}

/// Changes a setting that belongs to the file, not to a profile.
fn edit_global(
    path: &std::path::Path,
    change: impl FnOnce(&mut config::ConfigFile) -> Result<()>,
) -> Result<()> {
    let mut file = config::load(path)?;
    change(&mut file)?;
    config::save(path, &file)?;
    eprintln!("Saved in {}.", path.display());
    Ok(())
}

/// Changes the profile named by `--profile` (or the default one), creating it if needed.
fn edit(
    ctx: &Context,
    path: &std::path::Path,
    change: impl FnOnce(&mut config::Profile) -> Result<()>,
) -> Result<()> {
    let mut file = config::load(path)?;
    let name = ctx
        .overrides
        .profile
        .clone()
        .or_else(|| file.default_profile.clone())
        .unwrap_or_else(|| DEFAULT_PROFILE.to_owned());
    if name.trim().is_empty() || name.chars().any(char::is_control) {
        return Err(Failure::general(
            "A profile name cannot be empty or contain control characters.",
        ));
    }
    change(file.profiles.entry(name.clone()).or_default())?;
    config::save(path, &file)?;
    eprintln!("Saved profile `{name}` in {}.", path.display());
    Ok(())
}
