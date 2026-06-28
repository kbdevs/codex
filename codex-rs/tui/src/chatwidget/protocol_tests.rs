use super::completed_item_starts_next_agent_cycle;
use codex_app_server_protocol::DynamicToolCallStatus;
use codex_app_server_protocol::ThreadItem;
use codex_protocol::models::MessagePhase;
use pretty_assertions::assert_eq;
use serde_json::json;

#[test]
fn completed_tool_items_start_the_next_agent_cycle() {
    let completed_dynamic_tool = ThreadItem::DynamicToolCall {
        id: "tool-1".to_string(),
        namespace: Some("functions".to_string()),
        tool: "lookup".to_string(),
        arguments: json!({ "query": "codex" }),
        status: DynamicToolCallStatus::Completed,
        content_items: None,
        success: Some(true),
        duration_ms: Some(20_000),
    };
    let running_dynamic_tool = ThreadItem::DynamicToolCall {
        id: "tool-2".to_string(),
        namespace: Some("functions".to_string()),
        tool: "lookup".to_string(),
        arguments: json!({ "query": "codex" }),
        status: DynamicToolCallStatus::InProgress,
        content_items: None,
        success: None,
        duration_ms: None,
    };
    let agent_message = ThreadItem::AgentMessage {
        id: "msg-1".to_string(),
        text: "Done".to_string(),
        phase: Some(MessagePhase::FinalAnswer),
        memory_citation: None,
    };
    let sleep = ThreadItem::Sleep {
        id: "sleep-1".to_string(),
        duration_ms: 20_000,
    };

    assert_eq!(
        (
            completed_item_starts_next_agent_cycle(&completed_dynamic_tool),
            completed_item_starts_next_agent_cycle(&running_dynamic_tool),
            completed_item_starts_next_agent_cycle(&agent_message),
            completed_item_starts_next_agent_cycle(&sleep),
        ),
        (true, false, false, true)
    );
}
