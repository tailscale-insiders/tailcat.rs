//! `tailcat genkey`: generate, list, or delete saved keys.

use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use clap::{ArgAction, Args};
use tailcat::{DerpMap, DerpNode, DerpRegion, FetchMode, FetchOptions, PresharedKey, PrivateKey};

use crate::cache::DiskDerpMapCache;
use crate::{Global, usagef};

#[derive(Args, Debug)]
pub struct GenkeyArgs {
    /// Generate a client identity key (no DERP region) and print its public key, for use with servers' --allow
    /// lists. The 'client-default' key is used automatically by client modes.
    #[arg(long)]
    client: bool,
    /// Force overwrite of existing key.
    #[arg(long)]
    force: bool,
    /// Delete the key named by --key instead of generating one.
    #[arg(long)]
    delete: bool,
    /// List saved key names and exit.
    #[arg(long)]
    list: bool,
    /// Region ID, code, or substring to use. Or hostname(s), comma-separated, to use custom DERP server(s).
    /// If 'auto', one is picked based on latency at each server startup. If 'list', list all regions.
    #[arg(long)]
    region: Option<String>,
    /// Discover the nearest DERP region once, now, and bake it into the key and tailcat address.
    #[arg(long)]
    fixed_region: bool,
    /// Embed the DERP map nodes in the tailcat address. Needs a region chosen now, so it implies
    /// --fixed-region unless --region names one.
    #[arg(long)]
    embed_derp_map: bool,
    /// Include a WireGuard pre-shared key in the generated server key and tailcat address (recommended).
    #[arg(long, value_name = "BOOL", num_args = 0..=1, default_missing_value = "true", action = ArgAction::Set)]
    psk: Option<bool>,
}

fn write_key(path: &std::path::Path, data: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(data.as_bytes())?;
    }
    #[cfg(not(unix))]
    std::fs::write(path, data)?;
    Ok(())
}

pub async fn genkey(g: &Global, a: GenkeyArgs) -> Result<ExitCode> {
    let key = g.key.clone().unwrap_or_default();
    let region_set = a.region.is_some();
    let mut region = a.region.clone().unwrap_or_else(|| "auto".into());

    if a.list {
        let dir = crate::keys::keys_dir()?;
        let mut names: Vec<String> = match std::fs::read_dir(&dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_suffix(".private.json")).map(String::from))
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        names.sort();
        for n in names {
            println!("{n}");
        }
        return Ok(ExitCode::SUCCESS);
    }
    if a.delete {
        if key.is_empty() {
            return Err(usagef!(
                "genkey --delete requires saying which key to delete with --key=<name> (see genkey --list)"
            ));
        }
        if crate::keys::is_path(&key) {
            return Err(usagef!("can't delete key {key:?}; it's a path"));
        }
        std::fs::remove_file(crate::keys::key_path(&key)?)?;
        return Ok(ExitCode::SUCCESS);
    }
    if key.is_empty() && region != "list" {
        if a.client {
            return Err(usagef!(
                "genkey requires a --key=<name>; client modes automatically load the key named \"client-default\" when it exists, making it the usual choice"
            ));
        }
        return Err(usagef!(
            "genkey requires a --key=<name>; server mode automatically loads the key named \"default\" when it exists, making it the usual choice"
        ));
    }
    if a.client {
        if region_set || a.fixed_region || a.embed_derp_map {
            return Err(usagef!(
                "genkey --client does not take --region, --fixed-region or --embed-derp-map; client keys have no DERP region"
            ));
        }
        if a.psk.is_some() {
            return Err(usagef!("genkey --client does not take --psk; pre-shared keys belong to server addresses"));
        }
        if key == "default" {
            return Err(usagef!(
                "genkey --client with --key=default is probably a mistake: \"default\" is the name server mode loads automatically, and client modes load \"client-default\", so you likely want --key=client-default"
            ));
        }
    }
    if a.fixed_region {
        if region_set {
            return Err(usagef!("genkey --fixed-region and --region are mutually exclusive"));
        }
        region.clear(); // pick the best region now
    }
    if a.embed_derp_map {
        if region_set && region == "auto" {
            return Err(usagef!(
                "genkey --embed-derp-map and --region=auto are mutually exclusive; embedding needs a region chosen now, so use --fixed-region or name a region with --region"
            ));
        }
        if region.contains('.') {
            return Err(usagef!(
                "genkey --embed-derp-map does not take DERP hostnames in --region; naming hosts already embeds them in the address"
            ));
        }
        if !region_set {
            region.clear();
        }
    }
    let path = crate::keys::key_path(if key.is_empty() { "unused" } else { &key })?;
    if !key.is_empty() {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        if path.exists() && !a.force && region != "list" {
            bail!("{} already exists; use --force to overwrite", path.display());
        }
    }

    let mut priv_key = PrivateKey::generate();
    if a.psk == Some(false) {
        priv_key.public.preshared_key = PresharedKey::default();
    }
    if a.client {
        write_key(&path, &priv_key.to_json_pretty())?;
        eprintln!("# wrote file to {}", path.display());
        println!("{}", priv_key.private.public());
        return Ok(ExitCode::SUCCESS);
    }

    let mut matched = String::new();
    if region == "auto" {
        priv_key.public.region_id = -1;
    } else if let Ok(n) = region.parse::<i32>() {
        priv_key.public.region_id = n;
    } else if region.contains('.') {
        let nodes = region.split(',').map(|h| DerpNode { host_name: h.to_string(), ..Default::default() }).collect();
        priv_key.public.region.push(DerpRegion { nodes, ..Default::default() });
    } else {
        matched = region.clone();
    }

    let mut dm = DerpMap::default();
    if !matched.is_empty() || region.is_empty() || a.embed_derp_map {
        let cache = DiskDerpMapCache;
        dm = tokio::time::timeout(
            Duration::from_secs(10),
            tailcat::derpmap::fetch_derp_map(FetchOptions {
                url: Some(&g.derpmap_url),
                mode: FetchMode::Server,
                cache: Some(&cache),
            }),
        )
        .await
        .map_err(|_| anyhow!("derpmap fetch: timeout"))?
        .map_err(|e| anyhow!("derpmap fetch: {e}"))?;
    }
    if region.is_empty() {
        let id = tailcat::netcheck::pick_best_region(&dm)
            .await?
            .ok_or_else(|| anyhow!("couldn't determine the closest DERP region; specify --region"))?;
        priv_key.public.region_id = id;
    }
    let ci = &mut priv_key.public;
    if !matched.is_empty() {
        match tailcat::derpmap::find_region(&dm, &matched) {
            Some(id) => ci.region_id = id,
            None => {
                for r in dm.regions.values() {
                    eprintln!("  {:3} {} {}", r.region_id, r.region_code, r.region_name);
                }
                if matched == "list" {
                    return Ok(ExitCode::SUCCESS);
                }
                bail!("\nno region found matching {matched:?}");
            }
        }
    }
    if a.embed_derp_map {
        let mut reg = dm
            .regions
            .get(&ci.region_id)
            .cloned()
            .ok_or_else(|| anyhow!("no DERP region {} in the DERP map; can't embed its nodes", ci.region_id))?;
        reg.nodes.truncate(2);
        for n in &mut reg.nodes {
            n.ipv6.clear();
        }
        ci.region.push(reg);
        ci.region_id = 0;
    }
    write_key(&path, &priv_key.to_json_pretty())?;
    eprintln!("# wrote file to {}", path.display());
    println!("{}", priv_key.public.addr());
    Ok(ExitCode::SUCCESS)
}
