// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Glowfly Identity Systems Co.,Ltd
use std::path::{Path, PathBuf};

pub fn resolve(repo: &Path, explicit: Option<&Path>) -> Result<PathBuf, String> {
    let selected = if let Some(path) = explicit {
        if path.is_absolute() { path.to_path_buf() } else { repo.join(path) }
    } else {
        let candidates = [repo.join("sdk/proto"), repo.join("proto")];
        let present: Vec<_> = candidates.iter().filter(|p| p.is_dir()).collect();
        match present.as_slice() {
            [path] => (*path).clone(),
            [] => return Err("No proto directory: provide sdk/proto or PAIL_PROTO_DIR".into()),
            _ => return Err("Ambiguous proto layout: set PAIL_PROTO_DIR explicitly".into()),
        }
    };
    for name in ["pail.proto", "token_service.proto"] {
        if !selected.join(name).is_file() {
            return Err(format!("Missing required proto: {}", selected.join(name).display()));
        }
    }
    selected.canonicalize().map_err(|e| format!("{}: {e}", selected.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn rejects_missing_and_ambiguous_without_silent_fallback() {
        let root = std::env::temp_dir().join(format!("pail-proto-layout-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        assert!(resolve(&root, None).unwrap_err().contains("No proto"));
        for layout in ["sdk/proto", "proto"] {
            let path = root.join(layout);
            fs::create_dir_all(&path).unwrap();
            for name in ["pail.proto", "token_service.proto"] { fs::write(path.join(name), "syntax = \"proto3\";").unwrap(); }
        }
        assert!(resolve(&root, None).unwrap_err().contains("Ambiguous"));
        assert!(resolve(&root, Some(Path::new("missing"))).unwrap_err().contains("Missing required"));
        assert_eq!(resolve(&root, Some(Path::new("sdk/proto"))).unwrap(), root.join("sdk/proto").canonicalize().unwrap());
        fs::remove_dir_all(root.join("proto")).unwrap();
        assert_eq!(resolve(&root, None).unwrap(), root.join("sdk/proto").canonicalize().unwrap());
        fs::remove_file(root.join("sdk/proto/token_service.proto")).unwrap();
        assert!(resolve(&root, None).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
