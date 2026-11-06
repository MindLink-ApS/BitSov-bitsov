//! Keep node data directories out of version control.
//!
//! A data directory holds the mnemonic, identity, databases and channel
//! backups. None of it is source, so every directory the node initializes gets
//! a `.gitignore` that ignores everything, and the operator is told when the
//! directory sits inside a git working tree.
use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

/// File name written into the data directory.
pub const GITIGNORE_FILE: &str = ".gitignore";

/// Ignore everything, including this file, so the directory never shows up.
const GITIGNORE_CONTENTS: &str = "# Written by konsensus: node data is not source.\n*\n";

/// Upper bound on parent directories inspected for a `.git` entry.
const MAX_ANCESTORS: usize = 64;

/// Suggested data directory outside any source checkout.
pub const SUGGESTED_DATA_DIR: &str = "~/bitsov-node";

/// Write `<dir>/.gitignore` ignoring everything. An existing file (or any
/// other entry by that name) is left untouched. Returns whether it was written.
pub fn ensure_gitignore(dir: &Path) -> Result<bool> {
    let path = dir.join(GITIGNORE_FILE);
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(mut file) => {
            file.write_all(GITIGNORE_CONTENTS.as_bytes())
                .and_then(|()| file.sync_all())
                .with_context(|| format!("failed to write {}", path.display()))?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(e).with_context(|| format!("failed to create {}", path.display())),
    }
}

/// The root of the git working tree containing `dir`, if any.
///
/// Walks `dir` and its parents (bounded) looking for a `.git` directory or
/// file (worktrees and submodules use a file). Does not run git.
pub fn enclosing_git_worktree(dir: &Path) -> Option<PathBuf> {
    let start = std::fs::canonicalize(dir)
        .or_else(|_| std::path::absolute(dir))
        .ok()?;
    start
        .ancestors()
        .take(MAX_ANCESTORS)
        .find(|candidate| std::fs::symlink_metadata(candidate.join(".git")).is_ok())
        .map(Path::to_path_buf)
}

/// Operator-facing notice for a data directory inside a git working tree.
pub fn git_worktree_warning(dir: &Path, worktree: &Path) -> String {
    format!(
        "WARNING: node data directory {} is inside the git working tree at {}.\n\
         \x20        Node secrets (mnemonic, identity, databases, channel backups) should live\n\
         \x20        outside source checkouts. A {GITIGNORE_FILE} ignoring everything is kept in the\n\
         \x20        data directory, but prefer a location such as {SUGGESTED_DATA_DIR}\n\
         \x20        (konsensus init --dir {SUGGESTED_DATA_DIR}).",
        dir.display(),
        worktree.display(),
    )
}

/// Ensure the data directory's `.gitignore` and warn (never refuse) when the
/// directory is inside a git working tree.
pub fn prepare(dir: &Path) -> Result<()> {
    ensure_gitignore(dir)?;
    if let Some(worktree) = enclosing_git_worktree(dir) {
        eprintln!("{}", git_worktree_warning(dir, &worktree));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gitignore_is_created_once_and_ignores_everything() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ensure_gitignore(dir.path()).unwrap());
        let written = std::fs::read_to_string(dir.path().join(GITIGNORE_FILE)).unwrap();
        assert!(written.lines().any(|line| line == "*"));
        assert!(!ensure_gitignore(dir.path()).unwrap());
        assert_eq!(
            std::fs::read_to_string(dir.path().join(GITIGNORE_FILE)).unwrap(),
            written
        );
    }

    #[test]
    fn existing_gitignore_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(GITIGNORE_FILE);
        std::fs::write(&path, "custom\n").unwrap();
        assert!(!ensure_gitignore(dir.path()).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "custom\n");
    }

    #[cfg(unix)]
    #[test]
    fn gitignore_symlink_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        let link = dir.path().join(GITIGNORE_FILE);
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(!ensure_gitignore(dir.path()).unwrap());
        assert!(!target.exists());
    }

    #[test]
    fn detects_git_directory_in_a_parent() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join(".git")).unwrap();
        let data = root.path().join("node-data").join("nested");
        std::fs::create_dir_all(&data).unwrap();
        assert_eq!(
            enclosing_git_worktree(&data),
            Some(std::fs::canonicalize(root.path()).unwrap())
        );
    }

    #[test]
    fn detects_git_file_used_by_worktrees() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join(".git"), "gitdir: /elsewhere\n").unwrap();
        let data = root.path().join("node-data");
        std::fs::create_dir(&data).unwrap();
        assert_eq!(
            enclosing_git_worktree(&data),
            Some(std::fs::canonicalize(root.path()).unwrap())
        );
    }

    #[test]
    fn detects_not_yet_created_directory_inside_worktree() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join(".git")).unwrap();
        assert!(enclosing_git_worktree(&root.path().join("missing")).is_some());
    }

    #[test]
    fn plain_directory_is_not_in_a_worktree() {
        let root = tempfile::tempdir().unwrap();
        let data = root.path().join("node-data");
        std::fs::create_dir(&data).unwrap();
        let found = enclosing_git_worktree(&data);
        // Only directories this test created are in scope; the temp root's own
        // ancestry is the environment's business.
        let root = std::fs::canonicalize(root.path()).unwrap();
        assert!(found.is_none_or(|worktree| !worktree.starts_with(&root)));
    }

    #[test]
    fn warning_names_both_paths_and_a_suggestion() {
        let text = git_worktree_warning(Path::new("/src/repo/node-data"), Path::new("/src/repo"));
        assert!(text.contains("/src/repo/node-data"));
        assert!(text.contains("git working tree at /src/repo"));
        assert!(text.contains(SUGGESTED_DATA_DIR));
    }

    #[test]
    fn prepare_writes_gitignore_and_does_not_refuse_inside_worktree() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join(".git")).unwrap();
        let data = root.path().join("node-data");
        std::fs::create_dir(&data).unwrap();
        prepare(&data).unwrap();
        assert!(data.join(GITIGNORE_FILE).is_file());
    }
}
