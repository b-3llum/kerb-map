//! kerb-chain CLI binary — clap-driven, single-file orchestrator.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use kerb_chain::{
    Credential, Engagement, Playbook, Runner,
    findings::{index_by_attack, load_findings},
    playbook::evaluate_condition,
    engagement::EngagementOpts,
};


#[derive(Parser, Debug)]
#[command(
    name = "kerb-chain",
    version,
    about = "Playbook-driven AD attack chain orchestrator (Rust port)",
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}


#[derive(Subcommand, Debug)]
enum Cmd {
    /// Execute a playbook against a kerb-map findings file.
    Run(RunArgs),
    /// Print the findings + which plays would activate (no execution).
    Show(ShowArgs),
}


#[derive(Parser, Debug)]
struct RunArgs {
    /// kerb-map JSON output (full_data shape or bare findings list).
    #[arg(long)]
    findings: PathBuf,

    /// Playbook name (matches a bundled file, e.g. `standard`) or full path.
    #[arg(long)]
    playbook: String,

    /// Seed credential username.
    #[arg(long)]
    operator_user: Option<String>,

    /// Seed password (literal). Prefer --operator-pass-env on shared hosts.
    #[arg(long)]
    operator_pass: Option<String>,

    /// Read seed password from this environment variable.
    #[arg(long)]
    operator_pass_env: Option<String>,

    /// Seed NT hash (alternative to password).
    #[arg(long)]
    operator_hash: Option<String>,

    #[arg(long)] domain:        Option<String>,
    #[arg(long, value_name = "DC_IP")] dc_ip: Option<String>,
    #[arg(long)] run_dir:       Option<PathBuf>,

    /// Render commands and evaluate conditions without spawning subprocesses.
    #[arg(long)] dry_run:    bool,

    /// Enable plays gated as `requires_aggressive: true`.
    #[arg(long)] aggressive: bool,

    /// Suppress per-play progress output.
    #[arg(long)] quiet:      bool,

    /// Restrict to plays whose category matches.
    #[arg(long, value_name = "CATEGORY")]
    only_category: Option<String>,
}


#[derive(Parser, Debug)]
struct ShowArgs {
    #[arg(long)] findings: PathBuf,
    /// Optional: report which plays would activate against the findings.
    #[arg(long)] playbook: Option<String>,
}


fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Run(args)  => cmd_run(args),
        Cmd::Show(args) => cmd_show(args),
    }
}


// ─────────────────────────────────────────────────────────────────── //
//  Subcommands                                                        //
// ─────────────────────────────────────────────────────────────────── //


fn cmd_run(args: RunArgs) -> Result<()> {
    let findings = load_findings(&args.findings)?;
    if findings.is_empty() {
        println!("[!] {}: no findings to chain on; exiting.", args.findings.display());
        return Ok(());
    }

    let operator = resolve_operator(&args)?;
    let pb_path  = resolve_playbook(&args.playbook)?;
    let mut playbook = Playbook::from_path(&pb_path)?;

    let opts = EngagementOpts {
        domain:     args.domain,
        dc_ip:      args.dc_ip,
        operator:   operator,
        run_dir:    args.run_dir,
        dry_run:    args.dry_run,
        ..Default::default()
    };
    let mut engagement = Engagement::from_findings(findings, opts)?;

    if let Some(cat) = &args.only_category {
        playbook.plays.retain(|p| &p.category == cat);
    }

    println!(
        "[*] kerb-chain: domain={}  dc={}  findings={}  playbook={}  {}{}",
        if engagement.domain.is_empty() { "?".to_string() } else { engagement.domain.clone() },
        if engagement.dc_ip.is_empty()  { "?".to_string() } else { engagement.dc_ip.clone()  },
        engagement.findings.len(),
        playbook.name,
        if args.dry_run { "dry-run" } else { "live" },
        if args.aggressive { " aggressive" } else { "" },
    );
    println!("    run_dir: {}", engagement.run_dir.display());

    Runner::new(&playbook, &mut engagement)
        .aggressive(args.aggressive)
        .verbose(!args.quiet)
        .run()?;

    let history_count = engagement.history.len();
    let cred_count    = engagement.loot.credentials.len();
    let ticket_count  = engagement.loot.tickets.len();
    let cert_count    = engagement.loot.certificates.len();
    let host_count    = engagement.loot.owned_hosts.len();
    let journal       = engagement.write_journal()?;

    println!("\n[*] {} play records written to {}",
             history_count, journal.display());
    println!("    loot: {cred_count} creds, {ticket_count} tickets, \
              {cert_count} certs, {host_count} owned hosts");
    Ok(())
}


fn cmd_show(args: ShowArgs) -> Result<()> {
    let findings = load_findings(&args.findings)?;
    let grouped  = index_by_attack(&findings);
    println!("[*] {} findings across {} attack types",
             findings.len(), grouped.len());
    let mut by_count: Vec<(&String, &Vec<_>)> = grouped.iter().collect();
    by_count.sort_by_key(|(_, v)| std::cmp::Reverse(v.len()));
    for (attack, group) in by_count {
        println!("  {:>4}  {}", group.len(), attack);
    }

    if let Some(pb) = &args.playbook {
        let pb_path = resolve_playbook(pb)?;
        let playbook = Playbook::from_path(&pb_path)?;
        // Build a dry-run engagement so condition evaluation can read state.
        let opts = EngagementOpts { dry_run: true, ..Default::default() };
        let engagement = Engagement::from_findings(findings.clone(), opts)?;

        println!("\n[*] playbook '{}' — plays that would activate now:", playbook.name);
        for play in &playbook.plays {
            if play.per == "finding" {
                let hits = findings.iter().filter(|f| {
                    evaluate_condition(&play.when, Some(f), &engagement)
                }).count();
                if hits > 0 {
                    println!("  ✓ {:30}  ×{:<3} ({})", play.name, hits, play.category);
                }
            } else if evaluate_condition(&play.when, None, &engagement) {
                println!("  ✓ {:30}  ×1   ({})", play.name, play.category);
            }
        }
    }
    Ok(())
}


// ─────────────────────────────────────────────────────────────────── //
//  Helpers                                                            //
// ─────────────────────────────────────────────────────────────────── //


fn resolve_operator(args: &RunArgs) -> Result<Option<Credential>> {
    let user = match &args.operator_user {
        Some(u) => u.clone(),
        None    => return Ok(None),
    };

    if let Some(h) = &args.operator_hash {
        let cred = Credential::new(user, "")
            .with_hash(h.clone())
            .with_source("cli");
        cred.validate()?;
        return Ok(Some(cred));
    }

    if let Some(env_var) = &args.operator_pass_env {
        let pw = std::env::var(env_var)
            .with_context(|| format!("env var {env_var} not set"))?;
        let cred = Credential::new(user, "")
            .with_password(pw)
            .with_source("cli");
        cred.validate()?;
        return Ok(Some(cred));
    }

    if let Some(pw) = &args.operator_pass {
        let cred = Credential::new(user, "")
            .with_password(pw.clone())
            .with_source("cli");
        cred.validate()?;
        return Ok(Some(cred));
    }

    Ok(None)
}


fn resolve_playbook(name_or_path: &str) -> Result<PathBuf> {
    let p = PathBuf::from(name_or_path);
    if p.exists() {
        return Ok(p);
    }
    // Bundled playbooks live next to the Python package, since the Rust
    // port shares them. Try a few sensible roots.
    let candidates = [
        // Relative to the binary (cargo install layout)
        std::env::current_exe()
            .ok()
            .and_then(|b| b.parent().map(|p| p.to_path_buf()))
            .map(|d| d.join(format!("playbooks/{name_or_path}.yaml"))),
        // Relative to CWD (development checkout)
        Some(PathBuf::from(format!("kerb_chain/playbooks/{name_or_path}.yaml"))),
        Some(PathBuf::from(format!("../kerb_chain/playbooks/{name_or_path}.yaml"))),
    ];
    for cand in candidates.into_iter().flatten() {
        if cand.exists() {
            return Ok(cand);
        }
    }
    bail!("playbook '{name_or_path}' not found (tried literal path and bundled locations)");
}


fn _ensure_path(p: &Path) -> &Path { p }   // keep clippy quiet on unused-self for resolve_playbook
