//! kerb-chain — playbook-driven AD attack chain orchestrator.
//!
//! The Rust port is structured so the Python and Rust runtimes are
//! interchangeable: same YAML playbook format, same `journal.json`
//! schema on disk, same condition grammar. Operators can run either
//! against the same engagement directory and the histories interleave.
//!
//! Public surface:
//! ```ignore
//! use kerb_chain::{Engagement, Playbook, Runner, load_findings};
//!
//! let findings = load_findings("scan.json")?;
//! let mut eng  = Engagement::from_findings(findings, /* opts */)?;
//! let pb       = Playbook::from_path("playbooks/standard.yaml")?;
//! Runner::new(&pb, &mut eng).run()?;
//! ```

pub mod engagement;
pub mod findings;
pub mod playbook;
pub mod runner;

pub use engagement::{Credential, Engagement, Loot, OwnedHost, PlayRecord};
pub use findings::{index_by_attack, load_findings};
pub use playbook::{CaptureRule, Play, Playbook, evaluate_condition};
pub use runner::Runner;
