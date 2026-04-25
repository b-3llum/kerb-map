//! Runner — sequential walker that turns plays into subprocess calls.
//!
//! Mirrors `kerb_chain/runner.py`. Same dry-run semantics, same
//! aggressive-gating, same capture-rule wiring, same journal output.

use std::collections::{BTreeMap, BTreeSet};
use std::process::{Command as ProcCommand, Stdio};
use std::time::{Duration, Instant};

use anyhow::Result;
use chrono::Utc;
use regex::RegexBuilder;

use crate::engagement::{
    Credential, Engagement, OwnedHost, PlayRecord, resolve_under_run_dir,
};
use crate::findings::Finding;
use crate::playbook::{CaptureRule, Command, Play, Playbook, evaluate_condition};


pub struct Runner<'a> {
    playbook:   &'a Playbook,
    engagement: &'a mut Engagement,
    aggressive: bool,
    verbose:    bool,
    enqueued:   BTreeSet<String>,
}


impl<'a> Runner<'a> {
    pub fn new(playbook: &'a Playbook, engagement: &'a mut Engagement) -> Self {
        Self {
            playbook,
            engagement,
            aggressive: false,
            verbose:    true,
            enqueued:   BTreeSet::new(),
        }
    }

    pub fn aggressive(mut self, on: bool) -> Self { self.aggressive = on; self }
    pub fn verbose(mut self, on: bool)    -> Self { self.verbose    = on; self }

    /// Run the whole playbook. Plays are seeded in declaration order;
    /// `on_success` adds follow-ups to the queue (each play name is
    /// only ever enqueued once per run — no cycles, and a play named
    /// in `on_success` that's also in the seed list does not re-run).
    pub fn run(&mut self) -> Result<()> {
        // Materialise the seed list of (play_index, finding_index_or_none).
        // We index into the playbook to keep the borrow checker happy
        // and avoid cloning each play.
        let mut queue: Vec<(usize, Option<usize>)> =
            (0..self.playbook.plays.len()).map(|i| (i, None)).collect();

        // Pre-populate the enqueued-set with everything in the seed
        // queue so a play named in another play's `on_success` doesn't
        // run twice. Without this, [a, b] with a.on_success=[b] runs b
        // once for the seed and once for the follow-up.
        for play in &self.playbook.plays {
            self.enqueued.insert(play.name.clone());
        }

        let mut i = 0;
        while i < queue.len() {
            let (play_idx, finding_idx) = queue[i];
            i += 1;
            self.run_one(play_idx, finding_idx, &mut queue)?;
        }
        Ok(())
    }

    fn run_one(
        &mut self,
        play_idx:    usize,
        finding_idx: Option<usize>,
        queue:       &mut Vec<(usize, Option<usize>)>,
    ) -> Result<()> {
        // Snapshot the play data we need so we can drop the borrow on
        // self.playbook before mutating self.engagement.
        let play         = self.playbook.plays[play_idx].clone();
        let finding_owned: Option<Finding> = finding_idx
            .and_then(|i| self.engagement.findings.get(i).cloned());

        if play.requires_aggressive && !self.aggressive {
            self.record_skip(&play, "requires --aggressive");
            return Ok(());
        }

        if play.per == "finding" && finding_idx.is_none() {
            // Expand into one execution per matching finding.
            for (idx, f) in self.engagement.findings.iter().enumerate() {
                if evaluate_condition(&play.when, Some(f), self.engagement) {
                    queue.push((play_idx, Some(idx)));
                }
            }
            return Ok(());
        }

        if !evaluate_condition(&play.when, finding_owned.as_ref(), self.engagement) {
            self.record_skip(&play, "condition false");
            return Ok(());
        }

        let argv = self.render_command(&play.command, finding_owned.as_ref());
        if self.verbose {
            println!("\n[+] {}  →  {}", play.name, argv.join(" "));
        }

        if self.engagement.dry_run {
            self.record_play(&play, argv, None, "", "", BTreeMap::new(), Some("dry-run"));
            return Ok(());
        }

        let started = iso_now();
        let result = run_with_timeout(&argv, Duration::from_secs(play.timeout));

        match result {
            ExecResult::Ok { stdout, stderr, exit_code } => {
                let loot_added = self.apply_capture(
                    &play.capture, &stdout, &stderr, finding_owned.as_ref(),
                );
                self.engagement.history.push(PlayRecord {
                    play:        play.name.clone(),
                    command:     argv,
                    started_at:  started,
                    finished_at: iso_now(),
                    exit_code:   Some(exit_code),
                    stdout:      cap_string(&stdout, 4000),
                    stderr:      cap_string(&stderr, 2000),
                    loot_added,
                    skipped:     None,
                });
                if exit_code == 0 {
                    for follow in &play.on_success {
                        if let Some(next_idx) = self.playbook.plays
                            .iter()
                            .position(|p| &p.name == follow)
                        {
                            if !self.enqueued.contains(follow) {
                                self.enqueued.insert(follow.clone());
                                queue.push((next_idx, finding_idx));
                            }
                        }
                    }
                }
            }
            ExecResult::Timeout => {
                self.record_play(
                    &play, argv, None, "", "",
                    BTreeMap::new(),
                    Some(&format!("timeout after {}s", play.timeout)),
                );
            }
            ExecResult::NotFound(cmd) => {
                self.record_play(
                    &play, argv, None, "", "",
                    BTreeMap::new(),
                    Some(&format!("command not found: {cmd}")),
                );
            }
        }

        Ok(())
    }

    // ─────────────────────────────────────────────── capture ───── //

    fn apply_capture(
        &mut self,
        rule:    &CaptureRule,
        stdout:  &str,
        stderr:  &str,
        finding: Option<&Finding>,
    ) -> BTreeMap<String, usize> {
        let _ = stderr;  // reserved for future stderr-based capture
        let mut added: BTreeMap<String, usize> = BTreeMap::new();

        if let Some(target_tpl) = &rule.stdout_to_file {
            let rendered = self.engagement.render(target_tpl, finding);
            let target   = resolve_under_run_dir(&self.engagement.run_dir, &rendered);
            if let Some(parent) = target.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if std::fs::write(&target, stdout).is_ok() {
                if let Some(name) = target.file_name().map(|n| n.to_string_lossy().into_owned()) {
                    self.engagement.loot.files.insert(name, target.clone());
                }
                *added.entry("files".into()).or_insert(0) += 1;
            }
        }

        if let Some(pat) = &rule.cred_regex {
            // multi_line(true) matches Python's `re.MULTILINE` — playbook
            // regex authors use ^/$ to mean line boundaries, not whole-string
            // boundaries.
            if let Ok(re) = RegexBuilder::new(pat).multi_line(true).build() {
                for caps in re.captures_iter(stdout) {
                    let user = caps.name("user").map(|m| m.as_str().to_string());
                    let pass = caps.name("pass").map(|m| m.as_str().to_string());
                    if let (Some(u), Some(p)) = (user, pass) {
                        let attack = finding
                            .and_then(|f| f.get("attack").and_then(|v| v.as_str()))
                            .unwrap_or("play");
                        self.engagement.loot.credentials.push(
                            Credential::new(u, self.engagement.domain.clone())
                                .with_password(p)
                                .with_source(format!("capture:{attack}"))
                        );
                        *added.entry("credentials".into()).or_insert(0) += 1;
                    }
                }
            }
        }

        if let Some(pat) = &rule.cred_hash_regex {
            // multi_line(true) matches Python's `re.MULTILINE` — playbook
            // regex authors use ^/$ to mean line boundaries, not whole-string
            // boundaries.
            if let Ok(re) = RegexBuilder::new(pat).multi_line(true).build() {
                for caps in re.captures_iter(stdout) {
                    let user = caps.name("user").map(|m| m.as_str().to_string());
                    let h    = caps.name("hash").map(|m| m.as_str().to_string());
                    if let (Some(u), Some(h)) = (user, h) {
                        let attack = finding
                            .and_then(|f| f.get("attack").and_then(|v| v.as_str()))
                            .unwrap_or("play");
                        self.engagement.loot.credentials.push(
                            Credential::new(u, self.engagement.domain.clone())
                                .with_hash(h)
                                .with_source(format!("capture:{attack}"))
                        );
                        *added.entry("credentials".into()).or_insert(0) += 1;
                    }
                }
            }
        }

        if let Some(pattern) = &rule.files_glob {
            let pattern = self.engagement.run_dir.join(pattern).display().to_string();
            if let Ok(paths) = glob::glob(&pattern) {
                for entry in paths.flatten() {
                    if let Some(name) = entry
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                    {
                        self.engagement
                            .loot
                            .files
                            .entry(name)
                            .or_insert(entry.clone());
                        *added.entry("files".into()).or_insert(0) += 1;
                    }
                }
            }
        }

        if let Some(marker) = &rule.owned_marker {
            if stdout.contains(marker) {
                let host_tpl = rule.owned_host.as_deref().unwrap_or("{{finding.target}}");
                let host = self.engagement.render(host_tpl, finding);
                let attack = finding
                    .and_then(|f| f.get("attack").and_then(|v| v.as_str()))
                    .unwrap_or("play")
                    .to_string();
                self.engagement.loot.owned_hosts.push(OwnedHost {
                    name:        if host.is_empty() { "unknown".into() } else { host },
                    ip:          None,
                    via_play:    attack,
                    obtained_at: iso_now(),
                    notes:       String::new(),
                });
                *added.entry("owned_hosts".into()).or_insert(0) += 1;
            }
        }

        added
    }

    // ─────────────────────────────────────────── helpers / logging ── //

    fn render_command(&self, command: &Command, finding: Option<&Finding>) -> Vec<String> {
        match command {
            Command::Argv(argv) => argv
                .iter()
                .map(|a| self.engagement.render(a, finding))
                .collect(),
            Command::Shell(s) => {
                let rendered = self.engagement.render(s, finding);
                shell_words::split(&rendered).unwrap_or_else(|_| vec![rendered])
            }
        }
    }

    fn record_skip(&mut self, play: &Play, reason: &str) {
        let now = iso_now();
        self.engagement.history.push(PlayRecord {
            play:        play.name.clone(),
            command:     Vec::new(),
            started_at:  now.clone(),
            finished_at: now,
            exit_code:   None,
            stdout:      String::new(),
            stderr:      String::new(),
            loot_added:  BTreeMap::new(),
            skipped:     Some(reason.to_string()),
        });
        if self.verbose {
            println!("    [-] skipped: {reason}");
        }
    }

    fn record_play(
        &mut self,
        play:       &Play,
        argv:       Vec<String>,
        exit_code:  Option<i32>,
        stdout:     &str,
        stderr:     &str,
        loot_added: BTreeMap<String, usize>,
        skipped:    Option<&str>,
    ) {
        let now = iso_now();
        self.engagement.history.push(PlayRecord {
            play:        play.name.clone(),
            command:     argv,
            started_at:  now.clone(),
            finished_at: now,
            exit_code,
            stdout:      cap_string(stdout, 4000),
            stderr:      cap_string(stderr, 2000),
            loot_added,
            skipped:     skipped.map(|s| s.to_string()),
        });
    }
}


// ─────────────────────────────────────────────────────────────────── //
//  Subprocess execution                                               //
// ─────────────────────────────────────────────────────────────────── //


enum ExecResult {
    Ok { stdout: String, stderr: String, exit_code: i32 },
    Timeout,
    NotFound(String),
}


fn run_with_timeout(argv: &[String], timeout: Duration) -> ExecResult {
    if argv.is_empty() {
        return ExecResult::NotFound("(empty argv)".to_string());
    }

    let mut cmd = ProcCommand::new(&argv[0]);
    if argv.len() > 1 {
        cmd.args(&argv[1..]);
    }
    cmd.stdin(Stdio::null())
       .stdout(Stdio::piped())
       .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return ExecResult::NotFound(argv[0].clone());
        }
        Err(_) => return ExecResult::NotFound(argv[0].clone()),
    };

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                let mut stderr = String::new();
                if let Some(mut o) = child.stdout.take() {
                    use std::io::Read;
                    let _ = o.read_to_string(&mut stdout);
                }
                if let Some(mut e) = child.stderr.take() {
                    use std::io::Read;
                    let _ = e.read_to_string(&mut stderr);
                }
                return ExecResult::Ok {
                    stdout, stderr,
                    exit_code: status.code().unwrap_or(-1),
                };
            }
            Ok(None) => {
                if started.elapsed() > timeout {
                    let _ = child.kill();
                    return ExecResult::Timeout;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return ExecResult::Timeout,
        }
    }
}


fn iso_now() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%S+00:00").to_string()
}


fn cap_string(s: &str, max: usize) -> String {
    if s.len() <= max { return s.to_string(); }
    let start = s.len() - max;
    s[start..].to_string()
}
