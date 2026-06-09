use super::*;
use crate::history_cell::AgentMarkdownCell;
use crate::history_cell::AgentMessageCell;
use crate::history_cell::HistoryCell;
use crate::history_cell::UserHistoryCell;
use ratatui::text::Line;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

pub(crate) const EXPORT_HEADER: &str = "# Codex Chat Export";
const SECTION_MARKER_PREFIX: &str = "<!-- codex-export-section:";

impl App {
    pub(super) fn export_transcript_to_markdown(&mut self) {
        let cwd = self.chat_widget.status_line_cwd().to_path_buf();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or(0);
        let path = cwd.join(format!("codex-chat-export-{timestamp}.md"));
        let markdown = self.transcript_markdown();

        match std::fs::write(&path, markdown) {
            Ok(()) => {
                self.chat_widget.add_info_message(
                    format!("Exported chat history to {}", path.display()),
                    /*hint*/ None,
                );
            }
            Err(err) => {
                self.chat_widget.add_error_message(format!(
                    "Failed to export chat history to {}: {err}",
                    path.display()
                ));
            }
        }
    }

    fn transcript_markdown(&self) -> String {
        let mut out = String::from(EXPORT_HEADER);
        out.push_str("\n\n");
        for cell in &self.transcript_cells {
            if let Some(user) = cell.as_any().downcast_ref::<UserHistoryCell>() {
                push_section(&mut out, "User", &user.raw_lines());
            } else if let Some(agent) = cell.as_any().downcast_ref::<AgentMarkdownCell>() {
                push_section(&mut out, "Codex", &agent.raw_lines());
            } else if let Some(agent) = cell.as_any().downcast_ref::<AgentMessageCell>() {
                push_section(&mut out, "Codex", &agent.raw_lines());
            } else {
                push_section(&mut out, "Event", &cell.raw_lines());
            }
        }
        out
    }
}

fn push_section(out: &mut String, heading: &str, lines: &[Line<'static>]) {
    let body = lines_to_text(lines);
    if body.trim().is_empty() {
        return;
    }

    out.push_str(SECTION_MARKER_PREFIX);
    out.push(' ');
    out.push_str(heading);
    out.push_str(" -->\n");
    out.push_str("## ");
    out.push_str(heading);
    out.push_str("\n\n");
    out.push_str(body.trim_end());
    out.push_str("\n\n");
}

fn lines_to_text(lines: &[Line<'static>]) -> String {
    lines
        .iter()
        .map(line_to_text)
        .collect::<Vec<_>>()
        .join("\n")
}

fn line_to_text(line: &Line<'static>) -> String {
    line.spans
        .iter()
        .map(|span| span.content.as_ref())
        .collect::<String>()
}
