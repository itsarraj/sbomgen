use serde_json::Value as JsonValue;
use toml::Value as TomlValue;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Cargo,
    Npm,
    PyPi,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
}

/// Picks a parser from the lockfile's filename — the same auto-detection
/// convention `depaudit` uses elsewhere in this workspace. Only the three
/// lockfile shapes this crate actually parses are recognized; anything
/// else is a clean, named error rather than a silent no-op.
pub fn detect_and_parse(filename: &str, content: &str) -> Result<Vec<Component>, String> {
    if filename.ends_with("Cargo.lock") {
        parse_cargo_lock(content)
    } else if filename.ends_with("package-lock.json") {
        parse_npm_lock(content)
    } else if filename.ends_with("requirements.txt") {
        Ok(parse_requirements_txt(content))
    } else {
        Err(format!(
            "don't know how to parse {filename:?} — expected a Cargo.lock, package-lock.json, or requirements.txt"
        ))
    }
}

/// `Cargo.lock`'s `[[package]] name = "..." version = "..."` entries.
/// The lockfile's own root package (this crate/workspace member itself)
/// is included like any other entry — an SBOM for "what does this build
/// depend on" conventionally lists the subject too, and there's no
/// reliable way to distinguish "the package this lockfile is for" from
/// "a workspace member" from `Cargo.lock` alone.
pub fn parse_cargo_lock(content: &str) -> Result<Vec<Component>, String> {
    let parsed: TomlValue = content
        .parse()
        .map_err(|e| format!("not valid TOML: {e}"))?;
    let packages = parsed
        .get("package")
        .and_then(TomlValue::as_array)
        .ok_or_else(|| "no [[package]] entries found — is this a Cargo.lock?".to_string())?;

    Ok(packages
        .iter()
        .filter_map(|p| {
            let name = p.get("name")?.as_str()?.to_string();
            let version = p.get("version")?.as_str()?.to_string();
            Some(Component {
                name,
                version,
                ecosystem: Ecosystem::Cargo,
            })
        })
        .collect())
}

/// `package-lock.json`'s modern (`lockfileVersion` 2/3) `"packages"` map.
/// The root `""` entry is the project itself, not a dependency, and is
/// skipped (older `lockfileVersion` 1's nested `"dependencies"` tree
/// isn't parsed — see README).
pub fn parse_npm_lock(content: &str) -> Result<Vec<Component>, String> {
    let parsed: JsonValue =
        serde_json::from_str(content).map_err(|e| format!("not valid JSON: {e}"))?;
    let packages = parsed
        .get("packages")
        .and_then(JsonValue::as_object)
        .ok_or_else(|| {
            "no \"packages\" object — is this a lockfileVersion 2/3 package-lock.json?".to_string()
        })?;

    Ok(packages
        .iter()
        .filter_map(|(path, entry)| {
            if path.is_empty() {
                return None; // the project itself
            }
            let name = path
                .rsplit_once("node_modules/")
                .map(|(_, rest)| rest)
                .unwrap_or(path)
                .to_string();
            let version = entry.get("version")?.as_str()?.to_string();
            Some(Component {
                name,
                version,
                ecosystem: Ecosystem::Npm,
            })
        })
        .collect())
}

/// `requirements.txt`'s `name==version` exact pins. Range specifiers
/// (`>=`, `~=`, unpinned) have no single resolved version to report in an
/// SBOM and are skipped, not errored on.
pub fn parse_requirements_txt(content: &str) -> Vec<Component> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or(line).trim();
            let (name, version) = line.split_once("==")?;
            Some(Component {
                name: name.trim().to_string(),
                version: version.trim().to_string(),
                ecosystem: Ecosystem::PyPi,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_realistic_cargo_lock() {
        let content = r#"
version = 4

[[package]]
name = "serde"
version = "1.0.229"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "myapp"
version = "0.1.0"
"#;
        let components = parse_cargo_lock(content).unwrap();
        assert!(components.contains(&Component {
            name: "serde".to_string(),
            version: "1.0.229".to_string(),
            ecosystem: Ecosystem::Cargo,
        }));
        assert_eq!(components.len(), 2);
    }

    #[test]
    fn parses_a_realistic_npm_lockfile_v3() {
        let content = r#"{
            "name": "myapp",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "myapp", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.21"},
                "node_modules/@babel/core": {"version": "7.20.0"}
            }
        }"#;
        let components = parse_npm_lock(content).unwrap();
        assert!(components.contains(&Component {
            name: "lodash".to_string(),
            version: "4.17.21".to_string(),
            ecosystem: Ecosystem::Npm,
        }));
        assert!(components.contains(&Component {
            name: "@babel/core".to_string(),
            version: "7.20.0".to_string(),
            ecosystem: Ecosystem::Npm,
        }));
        assert_eq!(
            components.len(),
            2,
            "the root project entry must not be listed as a dependency"
        );
    }

    #[test]
    fn parses_requirements_txt_exact_pins_only() {
        let content = "\
# a comment
requests==2.28.0
flask>=2.0  # not an exact pin, skipped
numpy==1.24.0  # trailing comment stripped
";
        let components = parse_requirements_txt(content);
        assert_eq!(components.len(), 2);
        assert!(components.contains(&Component {
            name: "requests".to_string(),
            version: "2.28.0".to_string(),
            ecosystem: Ecosystem::PyPi,
        }));
    }

    #[test]
    fn malformed_cargo_lock_is_a_clean_error() {
        assert!(parse_cargo_lock("not toml at all {{{").is_err());
    }

    #[test]
    fn malformed_npm_lock_is_a_clean_error() {
        assert!(parse_npm_lock("not json").is_err());
    }

    #[test]
    fn detect_and_parse_picks_the_right_parser_from_filename() {
        let cargo = detect_and_parse(
            "Cargo.lock",
            "[[package]]\nname = \"a\"\nversion = \"1.0.0\"\n",
        )
        .unwrap();
        assert_eq!(cargo[0].ecosystem, Ecosystem::Cargo);

        let npm = detect_and_parse(
            "package-lock.json",
            r#"{"packages": {"": {}, "node_modules/a": {"version": "1.0.0"}}}"#,
        )
        .unwrap();
        assert_eq!(npm[0].ecosystem, Ecosystem::Npm);

        let py = detect_and_parse("requirements.txt", "a==1.0.0\n").unwrap();
        assert_eq!(py[0].ecosystem, Ecosystem::PyPi);
    }

    #[test]
    fn detect_and_parse_rejects_an_unrecognized_filename() {
        assert!(detect_and_parse("yarn.lock", "").is_err());
    }
}
