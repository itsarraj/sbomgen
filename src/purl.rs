use crate::lockfile::{Component, Ecosystem};

/// Percent-encodes the handful of characters that can legitimately show
/// up in a package name/version but aren't safe unescaped in a purl —
/// this is not a general URL-encoder, just enough for real package names
/// (npm scopes' `@`, and the rare `+`/space in a version).
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'@' => out.push_str("%40"),
            b' ' => out.push_str("%20"),
            _ => out.push(b as char),
        }
    }
    out
}

/// PyPI package-name normalization per PEP 503: lowercase, and any run of
/// `-`, `_`, or `.` collapses to a single `-`. `purl`'s own pypi type
/// spec requires this normalized form so `Django`, `django`, and
/// `django_` all resolve to the same purl.
fn normalize_pypi_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_was_sep = false;
    for c in name.chars() {
        if c == '-' || c == '_' || c == '.' {
            if !last_was_sep && !out.is_empty() {
                out.push('-');
            }
            last_was_sep = true;
        } else {
            out.push(c.to_ascii_lowercase());
            last_was_sep = false;
        }
    }
    out.trim_end_matches('-').to_string()
}

/// Builds the `pkg:<type>/...@<version>` purl (Package URL) string for a
/// component — the identifier CycloneDX, OSV, and most SBOM/vuln tooling
/// use to cross-reference the same package across formats.
pub fn purl_for(component: &Component) -> String {
    match component.ecosystem {
        Ecosystem::Cargo => format!(
            "pkg:cargo/{}@{}",
            percent_encode(&component.name),
            percent_encode(&component.version)
        ),
        Ecosystem::Npm => {
            // A scoped package's purl splits into a namespace (the
            // `@scope`, percent-encoded since `@` isn't a purl-safe
            // character in the namespace itself) and a name.
            if let Some((scope, name)) = component.name.split_once('/') {
                format!(
                    "pkg:npm/{}/{}@{}",
                    percent_encode(scope),
                    percent_encode(name),
                    percent_encode(&component.version)
                )
            } else {
                format!(
                    "pkg:npm/{}@{}",
                    percent_encode(&component.name),
                    percent_encode(&component.version)
                )
            }
        }
        Ecosystem::PyPi => format!(
            "pkg:pypi/{}@{}",
            normalize_pypi_name(&component.name),
            percent_encode(&component.version)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn comp(name: &str, version: &str, ecosystem: Ecosystem) -> Component {
        Component {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem,
        }
    }

    #[test]
    fn cargo_purl_shape() {
        assert_eq!(
            purl_for(&comp("serde", "1.0.229", Ecosystem::Cargo)),
            "pkg:cargo/serde@1.0.229"
        );
    }

    #[test]
    fn npm_purl_unscoped() {
        assert_eq!(
            purl_for(&comp("lodash", "4.17.21", Ecosystem::Npm)),
            "pkg:npm/lodash@4.17.21"
        );
    }

    #[test]
    fn npm_purl_scoped_package_encodes_the_at_sign() {
        assert_eq!(
            purl_for(&comp("@babel/core", "7.20.0", Ecosystem::Npm)),
            "pkg:npm/%40babel/core@7.20.0"
        );
    }

    #[test]
    fn pypi_purl_lowercases_and_normalizes_separators() {
        assert_eq!(
            purl_for(&comp("Django_Rest-Framework", "3.14.0", Ecosystem::PyPi)),
            "pkg:pypi/django-rest-framework@3.14.0"
        );
    }

    #[test]
    fn pypi_purl_plain_name() {
        assert_eq!(
            purl_for(&comp("requests", "2.31.0", Ecosystem::PyPi)),
            "pkg:pypi/requests@2.31.0"
        );
    }
}
