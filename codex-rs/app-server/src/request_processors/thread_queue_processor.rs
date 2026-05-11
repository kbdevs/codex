use super::*;
use codex_app_server_protocol::QueuedTurn;
use codex_app_server_protocol::ServerNotification;
use codex_app_server_protocol::ThreadQueueAddParams;
use codex_app_server_protocol::ThreadQueueAddResponse;
use codex_app_server_protocol::ThreadQueueChangedNotification;
use codex_app_server_protocol::ThreadQueueDeleteParams;
use codex_app_server_protocol::ThreadQueueDeleteResponse;
use codex_app_server_protocol::ThreadQueueListParams;
use codex_app_server_protocol::ThreadQueueListResponse;
use codex_app_server_protocol::ThreadQueueReorderParams;
use codex_app_server_protocol::ThreadQueueReorderResponse;

#[derive(Clone)]
pub(crate) struct ThreadQueueRequestProcessor {
    auth_manager: Arc<AuthManager>,
    thread_manager: Arc<ThreadManager>,
    outgoing: Arc<OutgoingMessageSender>,
    config: Arc<Config>,
    thread_state_manager: ThreadStateManager,
    state_db: Option<StateDbHandle>,
}

impl ThreadQueueRequestProcessor {
    pub(crate) fn new(
        auth_manager: Arc<AuthManager>,
        thread_manager: Arc<ThreadManager>,
        outgoing: Arc<OutgoingMessageSender>,
        config: Arc<Config>,
        thread_state_manager: ThreadStateManager,
        state_db: Option<StateDbHandle>,
    ) -> Self {
        Self {
            auth_manager,
            thread_manager,
            outgoing,
            config,
            thread_state_manager,
            state_db,
        }
    }

    pub(crate) async fn thread_queue_add(
        &self,
        params: ThreadQueueAddParams,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        TurnRequestProcessor::validate_v2_input_limit(&params.turn_start_params.input)?;
        let thread_id = parse_thread_id_for_request(params.thread_id.as_str())?;
        if params.turn_start_params.thread_id != params.thread_id {
            return Err(invalid_request(
                "threadId must match turnStartParams.threadId".to_string(),
            ));
        }
        let state_db = self.state_db_for_materialized_thread(thread_id).await?;
        let thread = self
            .thread_manager
            .get_thread(thread_id)
            .await
            .map_err(|_| invalid_request(format!("thread not found: {thread_id}")))?;
        thread
            .validate_turn_start_params(params.turn_start_params.clone())
            .await
            .map_err(queued_turn_validation_error)?;
        let turn_start_params_json =
            serde_json::to_string(&params.turn_start_params).map_err(|err| {
                internal_error(format!("failed to serialize queued turn params: {err}"))
            })?;
        let queued_turn = state_db
            .append_thread_queued_turn(thread_id, turn_start_params_json)
            .await
            .map_err(|err| internal_error(format!("failed to add queued turn: {err}")))?;
        let queued_turn = api_queued_turn_from_state(queued_turn)
            .map_err(|err| internal_error(format!("failed to decode queued turn params: {err}")))?;
        let queued_turns = read_api_thread_queue(&state_db, thread_id).await?;
        self.emit_thread_queue_changed_ordered(thread_id, queued_turns)
            .await;
        self.continue_queued_turn_if_idle(thread_id).await;
        Ok(Some(ThreadQueueAddResponse { queued_turn }.into()))
    }

    pub(crate) async fn thread_queue_list(
        &self,
        params: ThreadQueueListParams,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        let thread_id = parse_thread_id_for_request(params.thread_id.as_str())?;
        let state_db = self.state_db_for_materialized_thread(thread_id).await?;
        let queued_turns = read_api_thread_queue(&state_db, thread_id).await?;
        Ok(Some(ThreadQueueListResponse { queued_turns }.into()))
    }

    pub(crate) async fn thread_queue_delete(
        &self,
        params: ThreadQueueDeleteParams,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        let thread_id = parse_thread_id_for_request(params.thread_id.as_str())?;
        let state_db = self.state_db_for_materialized_thread(thread_id).await?;
        let deleted = state_db
            .delete_thread_queued_turn(thread_id, params.queued_turn_id.as_str())
            .await
            .map_err(|err| internal_error(format!("failed to delete queued turn: {err}")))?;
        if deleted {
            let queued_turns = read_api_thread_queue(&state_db, thread_id).await?;
            self.emit_thread_queue_changed_ordered(thread_id, queued_turns)
                .await;
        }
        Ok(Some(ThreadQueueDeleteResponse { deleted }.into()))
    }

    pub(crate) async fn thread_queue_reorder(
        &self,
        params: ThreadQueueReorderParams,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        let thread_id = parse_thread_id_for_request(params.thread_id.as_str())?;
        let state_db = self.state_db_for_materialized_thread(thread_id).await?;
        state_db
            .reorder_thread_queued_turns(thread_id, params.queued_turn_ids.as_slice())
            .await
            .map_err(|err| invalid_request(err.to_string()))?;
        let queued_turns = read_api_thread_queue(&state_db, thread_id).await?;
        self.emit_thread_queue_changed_ordered(thread_id, queued_turns.clone())
            .await;
        Ok(Some(ThreadQueueReorderResponse { queued_turns }.into()))
    }

    async fn continue_queued_turn_if_idle(&self, thread_id: ThreadId) {
        let Ok(thread) = self.thread_manager.get_thread(thread_id).await else {
            return;
        };
        if let Err(err) = thread.continue_queued_turn_if_idle().await {
            warn!("failed to continue queued turn for {thread_id}: {err}");
        }
    }

    pub(crate) async fn on_queued_turn_dispatched(
        &self,
        thread_id: ThreadId,
        turn_has_input: bool,
    ) {
        self.emit_thread_queue_snapshot(thread_id).await;
        if !turn_has_input {
            return;
        }
        let Ok(thread) = self.thread_manager.get_thread(thread_id).await else {
            return;
        };
        self.start_memories_startup_task_for_thread(thread_id, thread)
            .await;
    }

    async fn start_memories_startup_task_for_thread(
        &self,
        thread_id: ThreadId,
        thread: Arc<CodexThread>,
    ) {
        let config_snapshot = thread.config_snapshot().await;
        codex_memories_write::start_memories_startup_task(
            Arc::clone(&self.thread_manager),
            Arc::clone(&self.auth_manager),
            thread_id,
            Arc::clone(&thread),
            thread.config().await,
            &config_snapshot.session_source,
        );
    }

    async fn state_db_for_materialized_thread(
        &self,
        thread_id: ThreadId,
    ) -> Result<StateDbHandle, JSONRPCErrorError> {
        if let Ok(thread) = self.thread_manager.get_thread(thread_id).await {
            if thread.rollout_path().is_none() {
                return Err(invalid_request(format!(
                    "ephemeral thread does not support persistent app-server state: {thread_id}"
                )));
            }
            if let Some(state_db) = thread.state_db() {
                return Ok(state_db);
            }
        } else {
            find_thread_path_by_id_str(
                &self.config.codex_home,
                &thread_id.to_string(),
                self.state_db.as_deref(),
            )
            .await
            .map_err(|err| {
                internal_error(format!("failed to locate thread id {thread_id}: {err}"))
            })?
            .ok_or_else(|| invalid_request(format!("thread not found: {thread_id}")))?;
        }

        self.state_db.clone().ok_or_else(|| {
            invalid_request(format!(
                "thread does not support persistent app-server state: {thread_id}"
            ))
        })
    }

    pub(crate) async fn emit_thread_queue_snapshot(&self, thread_id: ThreadId) {
        let state_db = match self.state_db_for_materialized_thread(thread_id).await {
            Ok(state_db) => state_db,
            Err(err) => {
                warn!(
                    "failed to open state db before emitting thread queue resume snapshot for {thread_id}: {}",
                    err.message
                );
                return;
            }
        };
        let listener_command_tx = {
            let thread_state = self.thread_state_manager.thread_state(thread_id).await;
            let thread_state = thread_state.lock().await;
            thread_state.listener_command_tx()
        };
        if let Some(listener_command_tx) = listener_command_tx {
            let command = ThreadListenerCommand::EmitThreadQueueSnapshot {
                state_db: state_db.clone(),
            };
            if listener_command_tx.send(command).is_ok() {
                return;
            }
            warn!(
                "failed to enqueue thread queue snapshot for {thread_id}: listener command channel is closed"
            );
        }
        send_thread_queue_snapshot_notification(&self.outgoing, thread_id, &state_db).await;
    }

    async fn emit_thread_queue_changed_ordered(
        &self,
        thread_id: ThreadId,
        queued_turns: Vec<QueuedTurn>,
    ) {
        let listener_command_tx = {
            let thread_state = self.thread_state_manager.thread_state(thread_id).await;
            let thread_state = thread_state.lock().await;
            thread_state.listener_command_tx()
        };
        if let Some(listener_command_tx) = listener_command_tx {
            let command = ThreadListenerCommand::EmitThreadQueueChanged {
                queued_turns: queued_turns.clone(),
            };
            if listener_command_tx.send(command).is_ok() {
                return;
            }
            warn!(
                "failed to enqueue thread queue update for {thread_id}: listener command channel is closed"
            );
        }
        self.outgoing
            .send_server_notification(ServerNotification::ThreadQueueChanged(
                ThreadQueueChangedNotification {
                    thread_id: thread_id.to_string(),
                    queued_turns,
                },
            ))
            .await;
    }
}

fn parse_thread_id_for_request(thread_id: &str) -> Result<ThreadId, JSONRPCErrorError> {
    ThreadId::from_string(thread_id)
        .map_err(|err| invalid_request(format!("invalid thread id: {err}")))
}

fn queued_turn_validation_error(err: CodexErr) -> JSONRPCErrorError {
    match err {
        CodexErr::InvalidRequest(message) => invalid_request(message),
        CodexErr::Io(err) => config_load_error(&err),
        err => internal_error(format!("failed to prepare turn start: {err}")),
    }
}

fn api_queued_turn_from_state(
    queued_turn: codex_state::ThreadQueuedTurn,
) -> anyhow::Result<QueuedTurn> {
    Ok(QueuedTurn {
        id: queued_turn.queued_turn_id,
        turn_start_params: serde_json::from_str(queued_turn.turn_start_params_json.as_str())?,
    })
}

async fn read_api_thread_queue(
    state_db: &StateDbHandle,
    thread_id: ThreadId,
) -> Result<Vec<QueuedTurn>, JSONRPCErrorError> {
    state_db
        .list_thread_queued_turns(thread_id)
        .await
        .map_err(|err| internal_error(format!("failed to read thread queue: {err}")))?
        .into_iter()
        .map(api_queued_turn_from_state)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| internal_error(format!("failed to decode queued turn params: {err}")))
}

pub(super) async fn send_thread_queue_snapshot_notification(
    outgoing: &Arc<OutgoingMessageSender>,
    thread_id: ThreadId,
    state_db: &StateDbHandle,
) {
    match read_api_thread_queue(state_db, thread_id).await {
        Ok(queued_turns) => {
            outgoing
                .send_server_notification(ServerNotification::ThreadQueueChanged(
                    ThreadQueueChangedNotification {
                        thread_id: thread_id.to_string(),
                        queued_turns,
                    },
                ))
                .await;
        }
        Err(err) => {
            warn!(thread_id = %thread_id, "{}", err.message);
        }
    }
}
