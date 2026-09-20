use serde::Serialize;

use crate::lockfile::Component;
use crate::purl::purl_for;

#[derive(Debug, Serialize)]
pub struct Bom {
    #[serde(rename = "bomFormat")]
    pub bom_format: &'static str,
    #[serde(rename = "specVersion")]
    pub spec_version: &'static str,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub version: u32,
    pub metadata: Metadata,
    pub components: Vec<ComponentEntry>,
}

#[derive(Debug, Serialize)]
pub struct Metadata {
    pub timestamp: String,
}

#[derive(Debug, Serialize)]
pub struct ComponentEntry {
    #[serde(rename = "type")]
    pub component_type: &'static str,
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    pub name: String,
    pub version: String,
    pub purl: String,
}

/// Builds a CycloneDX 1.5 JSON document (`bomFormat`/`specVersion`/
/// `components[].{type,name,version,purl}` — the real shape the
/// CycloneDX 1.5 JSON schema requires) from a resolved component list.
/// `timestamp`/`serial_number` are injected rather than computed inside
/// this function so tests can assert on deterministic output without
/// depending on wall-clock time or randomness.
pub fn build_bom(components: &[Component], timestamp: String, serial_number: String) -> Bom {
    let mut seen = std::collections::HashSet::new();
    let entries: Vec<ComponentEntry> = components
        .iter()
        .filter(|c| seen.insert((c.name.clone(), c.version.clone())))
        .map(|c| {
            let purl = purl_for(c);
            ComponentEntry {
                component_type: "library",
                bom_ref: purl.clone(),
                name: c.name.clone(),
                version: c.version.clone(),
                purl,
            }
        })
        .collect();

    Bom {
        bom_format: "CycloneDX",
        spec_version: "1.5",
        serial_number,
        version: 1,
        metadata: Metadata { timestamp },
        components: entries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::Ecosystem;

    fn comp(name: &str, version: &str, ecosystem: Ecosystem) -> Component {
        Component {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem,
        }
    }

    #[test]
    fn builds_the_correct_top_level_shape() {
        let bom = build_bom(
            &[],
            "2026-01-01T00:00:00Z".to_string(),
            "urn:uuid:test".to_string(),
        );
        assert_eq!(bom.bom_format, "CycloneDX");
        assert_eq!(bom.spec_version, "1.5");
        assert_eq!(bom.version, 1);
        assert!(bom.components.is_empty());
    }

    #[test]
    fn each_component_has_type_library_and_a_matching_purl_and_bom_ref() {
        let bom = build_bom(
            &[comp("serde", "1.0.229", Ecosystem::Cargo)],
            "2026-01-01T00:00:00Z".to_string(),
            "urn:uuid:test".to_string(),
        );
        let entry = &bom.components[0];
        assert_eq!(entry.component_type, "library");
        assert_eq!(entry.purl, "pkg:cargo/serde@1.0.229");
        assert_eq!(entry.bom_ref, entry.purl);
        assert_eq!(entry.name, "serde");
        assert_eq!(entry.version, "1.0.229");
    }

    #[test]
    fn duplicate_name_version_pairs_are_deduplicated() {
        let bom = build_bom(
            &[
                comp("serde", "1.0.229", Ecosystem::Cargo),
                comp("serde", "1.0.229", Ecosystem::Cargo),
            ],
            "2026-01-01T00:00:00Z".to_string(),
            "urn:uuid:test".to_string(),
        );
        assert_eq!(bom.components.len(), 1);
    }

    #[test]
    fn serializes_to_valid_json_with_expected_keys() {
        let bom = build_bom(
            &[comp("lodash", "4.17.21", Ecosystem::Npm)],
            "2026-01-01T00:00:00Z".to_string(),
            "urn:uuid:test".to_string(),
        );
        let json = serde_json::to_value(&bom).unwrap();
        assert_eq!(json["bomFormat"], "CycloneDX");
        assert_eq!(json["specVersion"], "1.5");
        assert!(json["serialNumber"]
            .as_str()
            .unwrap()
            .starts_with("urn:uuid:"));
        assert_eq!(json["components"][0]["type"], "library");
        assert_eq!(json["components"][0]["purl"], "pkg:npm/lodash@4.17.21");
        assert_eq!(json["components"][0]["bom-ref"], "pkg:npm/lodash@4.17.21");
    }
}
