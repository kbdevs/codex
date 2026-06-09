use super::*;
use pretty_assertions::assert_eq;

#[test]
fn parses_marked_export_without_splitting_markdown_headings() {
    let markdown = concat!(
        "# Codex Chat Export\n\n",
        "<!-- codex-export-section: User -->\n",
        "## User\n\n",
        "hello\n\n",
        "<!-- codex-export-section: Codex -->\n",
        "## Codex\n\n",
        "## Assistant heading\n\n",
        "body\n",
    );

    let sections = parse_exported_transcript(markdown).expect("valid export");

    assert_eq!(
        sections
            .iter()
            .map(|section| (section.kind, section.body.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (ImportSectionKind::User, "hello"),
            (ImportSectionKind::Codex, "## Assistant heading\n\nbody"),
        ]
    );
}

#[test]
fn parses_legacy_heading_export() {
    let markdown = "# Codex Chat Export\n\n## User\n\nhello\n\n## Codex\n\nhey\n";

    let sections = parse_exported_transcript(markdown).expect("valid export");

    assert_eq!(
        sections
            .iter()
            .map(|section| (section.kind, section.body.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (ImportSectionKind::User, "hello"),
            (ImportSectionKind::Codex, "hey"),
        ]
    );
}

#[test]
fn rejects_non_export_file() {
    let err = parse_exported_transcript("# Other\n\n## User\n\nhello")
        .expect_err("should reject non-export");

    assert_eq!(err, "file is not a Codex chat export");
}
