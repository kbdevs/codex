use super::*;
use crate::history_cell::AgentMarkdownCell;
use crate::history_cell::HistoryCell;
use crate::history_cell::PlainHistoryCell;
use crate::history_cell::UserHistoryCell;
use crate::history_cell::raw_lines_from_source;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

const SECTION_MARKER_PREFIX: &str = "<!-- codex-export-section:";
const SECTION_MARKER_SUFFIX: &str = "-->";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImportSectionKind {
    User,
    Codex,
    Event,
}

#[derive(Debug)]
struct ImportSection {
    kind: ImportSectionKind,
    body: String,
}

impl App {
    pub(super) fn import_transcript_from_markdown(&mut self, tui: &mut tui::Tui, raw_path: &str) {
        let path = match self.resolve_import_path(raw_path) {
            Ok(path) => path,
            Err(message) => {
                self.chat_widget.add_error_message(message);
                return;
            }
        };

        let markdown = match std::fs::read_to_string(&path) {
            Ok(markdown) => markdown,
            Err(err) => {
                self.chat_widget.add_error_message(format!(
                    "Failed to import chat history from {}: {err}",
                    path.display()
                ));
                return;
            }
        };

        let sections = match parse_exported_transcript(&markdown) {
            Ok(sections) => sections,
            Err(message) => {
                self.chat_widget.add_error_message(format!(
                    "Failed to import chat history from {}: {message}",
                    path.display()
                ));
                return;
            }
        };

        let cwd = self.chat_widget.status_line_cwd().to_path_buf();
        let imported_count = sections.len();
        for section in sections {
            let cell = imported_section_cell(section, &cwd);
            self.insert_imported_history_cell(tui, cell);
        }

        self.chat_widget.add_info_message(
            format!(
                "Imported {imported_count} chat history sections from {}",
                path.display()
            ),
            /*hint*/ None,
        );
    }

    fn resolve_import_path(&self, raw_path: &str) -> Result<PathBuf, String> {
        let raw_path = raw_path.trim();
        if raw_path.is_empty() {
            return Err("Usage: /import <path>".to_string());
        }

        let path = match shlex::split(raw_path) {
            Some(parts) if parts.len() == 1 => PathBuf::from(&parts[0]),
            Some(parts) if parts.len() > 1 => {
                return Err("Usage: /import <path>".to_string());
            }
            _ => PathBuf::from(raw_path),
        };

        if path.is_absolute() {
            Ok(path)
        } else {
            Ok(self.chat_widget.status_line_cwd().join(path))
        }
    }

    fn insert_imported_history_cell(&mut self, tui: &mut tui::Tui, cell: Arc<dyn HistoryCell>) {
        if let Some(Overlay::Transcript(overlay)) = &mut self.overlay {
            overlay.insert_cell(cell.clone());
        }
        self.transcript_cells.push(cell.clone());
        self.insert_history_cell_lines(
            tui,
            cell.as_ref(),
            self.chat_widget
                .history_wrap_width(tui.terminal.last_known_screen_size.width),
        );
    }
}

fn imported_section_cell(section: ImportSection, cwd: &Path) -> Arc<dyn HistoryCell> {
    match section.kind {
        ImportSectionKind::User => Arc::new(UserHistoryCell {
            message: section.body,
            text_elements: Vec::new(),
            local_image_paths: Vec::new(),
            remote_image_urls: Vec::new(),
        }),
        ImportSectionKind::Codex => Arc::new(AgentMarkdownCell::new(section.body, cwd)),
        ImportSectionKind::Event => {
            Arc::new(PlainHistoryCell::new(raw_lines_from_source(&section.body)))
        }
    }
}

fn parse_exported_transcript(markdown: &str) -> Result<Vec<ImportSection>, String> {
    let body = markdown.strip_prefix('\u{feff}').unwrap_or(markdown);
    let Some(after_header) = body.strip_prefix(super::transcript_export::EXPORT_HEADER) else {
        return Err("file is not a Codex chat export".to_string());
    };

    let sections = if after_header.contains(SECTION_MARKER_PREFIX) {
        parse_marked_sections(after_header)
    } else {
        parse_heading_sections(after_header)
    };

    let sections = sections
        .into_iter()
        .filter_map(|section| {
            let body = section.body.trim_matches('\n').to_string();
            (!body.trim().is_empty()).then_some(ImportSection {
                kind: section.kind,
                body,
            })
        })
        .collect::<Vec<_>>();

    if sections.is_empty() {
        Err("no importable chat sections found".to_string())
    } else {
        Ok(sections)
    }
}

fn parse_marked_sections(markdown: &str) -> Vec<ImportSection> {
    let mut sections = Vec::new();
    let mut current: Option<(ImportSectionKind, String)> = None;
    let mut skipping_export_heading = false;

    for line in markdown.lines() {
        if let Some(kind) = section_kind_from_marker(line) {
            push_current_section(&mut sections, &mut current);
            current = Some((kind, String::new()));
            skipping_export_heading = true;
            continue;
        }

        if skipping_export_heading {
            if section_kind_from_heading(line).is_some() || line.trim().is_empty() {
                if section_kind_from_heading(line).is_some() {
                    skipping_export_heading = false;
                }
                continue;
            }
            skipping_export_heading = false;
        }

        if let Some((_kind, body)) = &mut current {
            body.push_str(line);
            body.push('\n');
        }
    }

    push_current_section(&mut sections, &mut current);
    sections
}

fn parse_heading_sections(markdown: &str) -> Vec<ImportSection> {
    let mut sections = Vec::new();
    let mut current: Option<(ImportSectionKind, String)> = None;

    for line in markdown.lines() {
        if let Some(kind) = section_kind_from_heading(line) {
            push_current_section(&mut sections, &mut current);
            current = Some((kind, String::new()));
            continue;
        }

        if let Some((_kind, body)) = &mut current {
            body.push_str(line);
            body.push('\n');
        }
    }

    push_current_section(&mut sections, &mut current);
    sections
}

fn push_current_section(
    sections: &mut Vec<ImportSection>,
    current: &mut Option<(ImportSectionKind, String)>,
) {
    if let Some((kind, body)) = current.take() {
        sections.push(ImportSection { kind, body });
    }
}

fn section_kind_from_marker(line: &str) -> Option<ImportSectionKind> {
    let marker = line.trim();
    let rest = marker.strip_prefix(SECTION_MARKER_PREFIX)?.trim();
    let name = rest.strip_suffix(SECTION_MARKER_SUFFIX)?.trim();
    section_kind_from_name(name)
}

fn section_kind_from_heading(line: &str) -> Option<ImportSectionKind> {
    let heading = line.trim();
    let name = heading.strip_prefix("## ")?;
    section_kind_from_name(name)
}

fn section_kind_from_name(name: &str) -> Option<ImportSectionKind> {
    match name {
        "User" => Some(ImportSectionKind::User),
        "Codex" => Some(ImportSectionKind::Codex),
        "Event" => Some(ImportSectionKind::Event),
        _ => None,
    }
}

#[cfg(test)]
#[path = "transcript_import_tests.rs"]
mod tests;
