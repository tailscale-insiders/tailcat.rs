//! `tailcat genkey`: generate, list, or delete saved keys.

use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use clap::{ArgAction, Args};
use tailcat::{DerpMap, DerpNode, DerpRegion, FetchMode, PresharedKey, PrivateKey, RegionArg};

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
    region: Option<RegionArg>,
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

pub async fn genkey(g: &Global, a: GenkeyArgs) -> Result<()> {
    let key = g.key.as_deref().unwrap_or("");
    let region_set = a.region.is_some();
    let region = a.region.unwrap_or(RegionArg::Auto);
    let listing = region == RegionArg::List;
    // Whether to find the nearest region now, rather than at each start.
    let mut pick_now = false;

    if a.list {
        let mut names: Vec<String> = match std::fs::read_dir(crate::keys::keys_dir()?) {
            Ok(rd) => rd
                .filter_map(|e| e.ok()?.file_name().to_str()?.strip_suffix(".private.json").map(String::from))
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        names.sort();
        for n in names {
            println!("{n}");
        }
        return Ok(());
    }
    if a.delete {
        if key.is_empty() {
            return Err(usagef!(
                "genkey --delete requires saying which key to delete with --key=<name> (see genkey --list)"
            ));
        }
        if crate::keys::is_path(key) {
            return Err(usagef!("can't delete key {key:?}; it's a path"));
        }
        std::fs::remove_file(crate::keys::key_path(key)?)?;
        return Ok(());
    }
    if key.is_empty() && !listing {
        let (modes, default) = if a.client {
            ("client modes automatically load", "client-default")
        } else {
            ("server mode automatically loads", "default")
        };
        return Err(usagef!(
            "genkey requires a --key=<name>; {modes} the key named {default:?} when it exists, making it the usual choice"
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
        pick_now = true;
    }
    if a.embed_derp_map {
        if region_set && region == RegionArg::Auto {
            return Err(usagef!(
                "genkey --embed-derp-map and --region=auto are mutually exclusive; embedding needs a region chosen now, so use --fixed-region or name a region with --region"
            ));
        }
        if matches!(region, RegionArg::Hosts(_)) {
            return Err(usagef!(
                "genkey --embed-derp-map does not take DERP hostnames in --region; naming hosts already embeds them in the address"
            ));
        }
        if !region_set {
            pick_now = true;
        }
    }
    let path = crate::keys::key_path(if key.is_empty() { "unused" } else { key })?;
    if !key.is_empty() {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        // Fail early, before any network work; writing checks again.
        if path.exists() && !a.force && !listing {
            return Err(exists(&path));
        }
    }

    let mut priv_key = PrivateKey::generate();
    if a.psk == Some(false) {
        priv_key.public.preshared_key = PresharedKey::default();
    }
    let write = |k: &PrivateKey| -> Result<()> {
        let json = k.to_json_pretty();
        // Atomically, so racing runs can't clobber each other's key and a
        // crash can't leave a truncated one.
        let written = if a.force {
            crate::util::replace_private(&path, json.as_bytes())
        } else {
            crate::util::create_private(&path, json.as_bytes())
        };
        written.map_err(|e| match e.kind() {
            std::io::ErrorKind::AlreadyExists => exists(&path),
            _ => anyhow!("writing {}: {e}", path.display()),
        })?;
        eprintln!("# wrote file to {}", path.display());
        Ok(())
    };
    if a.client {
        write(&priv_key)?;
        println!("{}", priv_key.private.public());
        return Ok(());
    }

    let ci = &mut priv_key.public;
    let dm = if pick_now || a.embed_derp_map || matches!(region, RegionArg::Name(_) | RegionArg::List) {
        let fetch = tailcat::derpmap::fetch_derp_map(crate::cache::fetch_options(g, FetchMode::Server));
        tokio::time::timeout(Duration::from_secs(10), fetch)
            .await
            .map_err(|_| anyhow!("derpmap fetch: timeout"))?
            .map_err(|e| anyhow!("derpmap fetch: {e}"))?
    } else {
        DerpMap::default()
    };
    let list = || {
        for r in dm.regions.values() {
            eprintln!("  {:3} {} {}", r.region_id, r.region_code, r.region_name);
        }
    };
    if pick_now {
        ci.region_id = tailcat::netcheck::pick_best_region(&dm)
            .await?
            .ok_or_else(|| anyhow!("couldn't determine the closest DERP region; specify --region"))?;
    } else {
        match &region {
            // Picked at each server start.
            RegionArg::Auto => ci.region_id = -1,
            RegionArg::Id(n) => ci.region_id = *n,
            RegionArg::Hosts(hosts) => {
                let nodes = hosts.iter().map(|h| DerpNode { host_name: h.as_str().into(), ..Default::default() });
                ci.region.push(DerpRegion { nodes: nodes.collect(), ..Default::default() });
            }
            RegionArg::Name(n) => match region.find(&dm) {
                Some(id) => ci.region_id = id,
                None => {
                    list();
                    bail!("\nno region found matching {n:?}");
                }
            },
            RegionArg::List => {
                list();
                return Ok(());
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
            n.ipv6 = tailcat::NodeIp::Lookup;
        }
        ci.region.push(reg);
        ci.region_id = 0;
    }
    write(&priv_key)?;
    println!("{}", priv_key.public.addr());
    Ok(())
}

fn exists(path: &std::path::Path) -> anyhow::Error {
    anyhow!("{} already exists; use --force to overwrite", path.display())
}
