// GravityCode INS Extensions Initialization
//
// This module deploys embedded INS extensions on first run

use include_dir::{include_dir, Dir};
use std::env;
use std::fs;
use std::path::PathBuf;

/// Embedded GravityCode extensions directory
/// This will be populated at compile time if ../../extensions/ exists
#[cfg(gravitycode_extensions)]
static EXTENSIONS: Dir = include_dir!("$GRAVITYCODE_EXTENSIONS_DIR");

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Initialize GravityCode INS extensions
///
/// This function is called early in Codex startup to deploy
/// embedded INS knowledge base and agent configurations.
pub fn initialize_gravitycode() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(gravitycode_extensions))]
    {
        // No GravityCode extensions embedded, skip
        return Ok(());
    }

    #[cfg(gravitycode_extensions)]
    {
        let codex_home = get_codex_home()?;
        let marker = codex_home.join(".gravitycode-version");

        // Check if already installed or needs upgrade
        let needs_install = if marker.exists() {
            let installed_version = fs::read_to_string(&marker)?;
            installed_version.trim() != VERSION
        } else {
            true
        };

        if needs_install {
            deploy_extensions(&codex_home)?;
            fs::write(&marker, VERSION)?;
        }

        // Set environment variable for agent to access knowledge base
        let kb_path = codex_home.join(".gravitycode-extensions");
        unsafe {
            env::set_var("INS_KNOWLEDGE_BASE", &kb_path);
        }

        Ok(())
    }
}

#[cfg(gravitycode_extensions)]
fn deploy_extensions(codex_home: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {

    // Deploy to .gravitycode-extensions/
    let ext_dir = codex_home.join(".gravitycode-extensions");
    extract_dir(&EXTENSIONS, &ext_dir)?;

    // Install AGENTS.md
    if let Some(agents_md) = EXTENSIONS.get_file("agents/AGENTS.md") {
        let target = codex_home.join("AGENTS.md");
        if target.exists() {
            // Backup existing
            let backup = codex_home.join("AGENTS.md.backup");
            fs::copy(&target, &backup)?;
        }
        fs::write(&target, agents_md.contents())?;
    }

    // Install custom prompts
    if let Some(prompts_dir) = EXTENSIONS.get_dir("prompts") {
        let target_dir = codex_home.join("prompts");
        fs::create_dir_all(&target_dir)?;

        for file in prompts_dir.files() {
            if let Some(name) = file.path().file_name() {
                let target = target_dir.join(name);
                fs::write(&target, file.contents())?;
            }
        }
    }

    Ok(())
}

#[cfg(gravitycode_extensions)]
fn extract_dir(dir: &Dir, target: &PathBuf) -> std::io::Result<()> {
    use include_dir::DirEntry;

    fs::create_dir_all(target)?;

    for entry in dir.entries() {
        match entry {
            DirEntry::Dir(subdir) => {
                let new_target = target.join(subdir.path());
                extract_dir(subdir, &new_target)?;
            }
            DirEntry::File(file) => {
                let file_path = target.join(file.path());
                if let Some(parent) = file_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&file_path, file.contents())?;
            }
        }
    }
    Ok(())
}

fn get_codex_home() -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Ok(home) = env::var("CODEX_HOME") {
        Ok(PathBuf::from(home))
    } else {
        dirs::home_dir()
            .map(|h| h.join(".codex"))
            .ok_or_else(|| "Cannot find home directory".into())
    }
}
