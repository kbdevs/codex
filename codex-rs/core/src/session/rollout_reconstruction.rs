use super::*;
use crate::context::world_state::WorldStateSnapshot;
use crate::context_manager::is_user_turn_boundary;
use codex_protocol::protocol::SessionContextWindow;
use uuid::Uuid;

// Return value of `Session::reconstruct_history_from_rollout`, bundling the rebuilt history with
// the resume/fork hydration metadata derived from the same replay.
#[derive(Debug)]
pub(super) struct RolloutReconstruction {
    pub(super) history: Vec<ResponseItem>,
    pub(super) previous_turn_settings: Option<PreviousTurnSettings>,
    pub(super) reference_context_item: Option<TurnContextItem>,
    pub(super) world_state_baseline: Option<WorldStateSnapshot>,
    pub(super) window_number: u64,
    pub(super) first_window_id: Option<Uuid>,
    pub(super) previous_window_id: Option<Uuid>,
    pub(super) window_id: Option<Uuid>,
}

#[derive(Debug, Clone, Copy)]
struct ReconstructedWindow {
    number: u64,
    first_id: Option<Uuid>,
    previous_id: Option<Uuid>,
    id: Option<Uuid>,
}

#[derive(Debug, Default)]
enum TurnReferenceContextItem {
    /// No `TurnContextItem` has been seen for this replay span yet.
    ///
    /// This differs from `Cleared`: `NeverSet` means there is no evidence this turn ever
    /// established a baseline, while `Cleared` means a baseline existed and a later compaction
    /// invalidated it. Only the latter must emit an explicit clearing segment for resume/fork
    /// hydration.
    #[default]
    NeverSet,
    /// A previously established baseline was invalidated by later compaction.
    Cleared,
    /// The latest baseline established by this replay span.
    Latest(Box<TurnContextItem>),
}

#[derive(Debug, Default)]
struct ActiveReplaySegment<'a> {
    turn_id: Option<String>,
    counts_as_user_turn: bool,
    previous_turn_settings: Option<PreviousTurnSettings>,
    reference_context_item: TurnReferenceContextItem,
    world_state_replay: Vec<&'a RolloutItem>,
    base_replacement_history: Option<&'a [ResponseItem]>,
    rollout_suffix_after_base: Option<&'a [RolloutItem]>,
    window: Option<ReconstructedWindow>,
}

struct ReplayState<'a> {
    base_replacement_history: Option<&'a [ResponseItem]>,
    previous_turn_settings: Option<PreviousTurnSettings>,
    reference_context_item: TurnReferenceContextItem,
    world_state_replay: Vec<&'a RolloutItem>,
    window: Option<ReconstructedWindow>,
    pending_rollback_turns: usize,
    rollout_suffix: &'a [RolloutItem],
}

fn turn_ids_are_compatible(active_turn_id: Option<&str>, item_turn_id: Option<&str>) -> bool {
    active_turn_id
        .is_none_or(|turn_id| item_turn_id.is_none_or(|item_turn_id| item_turn_id == turn_id))
}

fn finalize_active_segment<'a>(
    active_segment: ActiveReplaySegment<'a>,
    state: &mut ReplayState<'a>,
) {
    // Thread rollback drops the newest surviving real user-message boundaries. In replay, that
    // means skipping the next finalized segments that contain a non-contextual
    // `EventMsg::UserMessage`.
    if state.pending_rollback_turns > 0 {
        if active_segment.counts_as_user_turn {
            state.pending_rollback_turns -= 1;
        }
        return;
    }

    state
        .world_state_replay
        .extend(active_segment.world_state_replay);

    // A surviving replacement-history checkpoint is a complete history base. Once we
    // know the newest surviving one, older rollout items do not affect rebuilt history.
    if state.base_replacement_history.is_none()
        && let Some(segment_base_replacement_history) = active_segment.base_replacement_history
    {
        state.base_replacement_history = Some(segment_base_replacement_history);
        if let Some(segment_rollout_suffix) = active_segment.rollout_suffix_after_base {
            state.rollout_suffix = segment_rollout_suffix;
        }
    }

    if state.window.is_none() {
        state.window = active_segment.window;
    }

    // `previous_turn_settings` come from the newest surviving user turn that established them.
    if state.previous_turn_settings.is_none() && active_segment.counts_as_user_turn {
        state.previous_turn_settings = active_segment.previous_turn_settings;
    }

    // `reference_context_item` comes from the newest surviving user turn baseline, or
    // from a surviving compaction that explicitly cleared that baseline.
    if matches!(
        state.reference_context_item,
        TurnReferenceContextItem::NeverSet
    ) && (active_segment.counts_as_user_turn
        || matches!(
            active_segment.reference_context_item,
            TurnReferenceContextItem::Cleared
        ))
    {
        state.reference_context_item = active_segment.reference_context_item;
    }
}

impl Session {
    pub(super) async fn reconstruct_history_from_rollout(
        &self,
        turn_context: &TurnContext,
        rollout_items: &[RolloutItem],
    ) -> RolloutReconstruction {
        let effective_rollout_items;
        let has_thread_rollback = rollout_items
            .iter()
            .any(|item| matches!(item, RolloutItem::EventMsg(EventMsg::ThreadRolledBack(_))));
        let has_persisted_turn_boundaries = rollout_items
            .iter()
            .any(|item| matches!(item, RolloutItem::EventMsg(EventMsg::TurnStarted(_))));
        let rollout_items = if has_thread_rollback && has_persisted_turn_boundaries {
            effective_rollout_items = rollout_items_after_thread_rollbacks(rollout_items);
            effective_rollout_items.as_slice()
        } else {
            rollout_items
        };

        // Replay metadata should already match the shape of the future lazy reverse loader, even
        // while history materialization still uses an eager bridge. Scan newest-to-oldest,
        // stopping once a surviving replacement-history checkpoint and the required resume metadata
        // are both known; then replay only the buffered surviving tail forward to preserve exact
        // history semantics.
        let has_legacy_compaction_without_window_number =
            rollout_items.iter().any(|item| {
                matches!(item, RolloutItem::Compacted(compacted) if compacted.window_number.is_none())
            });
        let initial_window = if has_legacy_compaction_without_window_number {
            None
        } else {
            rollout_items.iter().find_map(|item| match item {
                RolloutItem::SessionMeta(session_meta) => session_meta
                    .meta
                    .context_window
                    .as_ref()
                    .and_then(reconstructed_window_from_session_context_window),
                _ => None,
            })
        };
        let mut replay_state = ReplayState {
            base_replacement_history: None,
            previous_turn_settings: None,
            reference_context_item: TurnReferenceContextItem::NeverSet,
            world_state_replay: Vec::new(),
            window: None,
            // Rollback is "drop the newest N user turns". While scanning in reverse, that becomes
            // "skip the next N user-turn segments we finalize".
            pending_rollback_turns: 0,
            // Borrowed suffix of rollout items newer than the newest surviving replacement-history
            // checkpoint. If no such checkpoint exists, this remains the full rollout.
            rollout_suffix: rollout_items,
        };
        // Reverse replay accumulates rollout items into the newest in-progress turn segment until
        // we hit its matching `TurnStarted`, at which point the segment can be finalized.
        let mut active_segment: Option<ActiveReplaySegment<'_>> = None;

        for (index, item) in rollout_items.iter().enumerate().rev() {
            match item {
                RolloutItem::Compacted(compacted) => {
                    let active_segment =
                        active_segment.get_or_insert_with(ActiveReplaySegment::default);
                    active_segment.world_state_replay.push(item);
                    if active_segment.window.is_none()
                        && let Some(window_number) = compacted.window_number
                    {
                        active_segment.window = Some(ReconstructedWindow {
                            number: window_number,
                            first_id: compacted.first_window_id.as_deref().and_then(parse_uuid_v7),
                            previous_id: compacted
                                .previous_window_id
                                .as_deref()
                                .and_then(parse_uuid_v7),
                            id: compacted.window_id.as_deref().and_then(parse_uuid_v7),
                        });
                    }
                    // Looking backward, compaction clears any older baseline unless a newer
                    // `TurnContextItem` in this same segment has already re-established it.
                    if matches!(
                        active_segment.reference_context_item,
                        TurnReferenceContextItem::NeverSet
                    ) {
                        active_segment.reference_context_item = TurnReferenceContextItem::Cleared;
                    }
                    if active_segment.base_replacement_history.is_none()
                        && let Some(replacement_history) = &compacted.replacement_history
                    {
                        active_segment.base_replacement_history = Some(replacement_history);
                        active_segment.rollout_suffix_after_base =
                            Some(&rollout_items[index + 1..]);
                    }
                }
                RolloutItem::EventMsg(EventMsg::ThreadRolledBack(rollback)) => {
                    replay_state.pending_rollback_turns = replay_state
                        .pending_rollback_turns
                        .saturating_add(usize::try_from(rollback.num_turns).unwrap_or(usize::MAX));
                }
                RolloutItem::EventMsg(EventMsg::TurnComplete(event)) => {
                    let active_segment =
                        active_segment.get_or_insert_with(ActiveReplaySegment::default);
                    // Reverse replay often sees `TurnComplete` before any turn-scoped metadata.
                    // Capture the turn id early so later `TurnContext` / abort items can match it.
                    if active_segment.turn_id.is_none() {
                        active_segment.turn_id = Some(event.turn_id.clone());
                    }
                }
                RolloutItem::EventMsg(EventMsg::TurnAborted(event)) => {
                    if let Some(active_segment) = active_segment.as_mut() {
                        if active_segment.turn_id.is_none()
                            && let Some(turn_id) = &event.turn_id
                        {
                            active_segment.turn_id = Some(turn_id.clone());
                        }
                    } else if let Some(turn_id) = &event.turn_id {
                        active_segment = Some(ActiveReplaySegment {
                            turn_id: Some(turn_id.clone()),
                            ..Default::default()
                        });
                    }
                }
                RolloutItem::EventMsg(EventMsg::UserMessage(_)) => {
                    let active_segment =
                        active_segment.get_or_insert_with(ActiveReplaySegment::default);
                    active_segment.counts_as_user_turn = true;
                }
                RolloutItem::TurnContext(ctx) => {
                    let active_segment =
                        active_segment.get_or_insert_with(ActiveReplaySegment::default);
                    // `TurnContextItem` can attach metadata to an existing segment, but only a
                    // real `UserMessage` event should make the segment count as a user turn.
                    if active_segment.turn_id.is_none() {
                        active_segment.turn_id = ctx.turn_id.clone();
                    }
                    if turn_ids_are_compatible(
                        active_segment.turn_id.as_deref(),
                        ctx.turn_id.as_deref(),
                    ) {
                        active_segment.previous_turn_settings = Some(PreviousTurnSettings {
                            model: ctx.model.clone(),
                            comp_hash: ctx.comp_hash.clone(),
                            realtime_active: ctx.realtime_active,
                        });
                        if matches!(
                            active_segment.reference_context_item,
                            TurnReferenceContextItem::NeverSet
                        ) {
                            active_segment.reference_context_item =
                                TurnReferenceContextItem::Latest(Box::new(ctx.clone()));
                        }
                    }
                }
                RolloutItem::WorldState(_) => {
                    let active_segment =
                        active_segment.get_or_insert_with(ActiveReplaySegment::default);
                    active_segment.world_state_replay.push(item);
                }
                RolloutItem::EventMsg(EventMsg::TurnStarted(event)) => {
                    // `TurnStarted` is the oldest boundary of the active reverse segment.
                    if active_segment.as_ref().is_some_and(|active_segment| {
                        turn_ids_are_compatible(
                            active_segment.turn_id.as_deref(),
                            Some(event.turn_id.as_str()),
                        )
                    }) && let Some(active_segment) = active_segment.take()
                    {
                        finalize_active_segment(active_segment, &mut replay_state);
                    }
                }
                RolloutItem::ResponseItem(response_item) => {
                    let active_segment =
                        active_segment.get_or_insert_with(ActiveReplaySegment::default);
                    active_segment.counts_as_user_turn |= is_user_turn_boundary(response_item);
                }
                RolloutItem::InterAgentCommunication(_) => {
                    let active_segment =
                        active_segment.get_or_insert_with(ActiveReplaySegment::default);
                    active_segment.counts_as_user_turn = true;
                }
                RolloutItem::EventMsg(_)
                | RolloutItem::SessionMeta(_)
                | RolloutItem::InterAgentCommunicationMetadata { .. } => {}
            }

            if replay_state.base_replacement_history.is_some()
                && replay_state.previous_turn_settings.is_some()
                && !matches!(
                    replay_state.reference_context_item,
                    TurnReferenceContextItem::NeverSet
                )
            {
                // At this point we have both eager resume metadata values and the replacement-
                // history base for the surviving tail, so older rollout items cannot affect this
                // result.
                break;
            }
        }

        if let Some(active_segment) = active_segment.take() {
            finalize_active_segment(active_segment, &mut replay_state);
        }

        let fallback_window_number = u64::try_from(
            rollout_items
                .iter()
                .filter(|item| matches!(item, RolloutItem::Compacted(_)))
                .count(),
        )
        .unwrap_or(u64::MAX);

        let mut history = ContextManager::new();
        let mut saw_legacy_compaction_without_replacement_history = false;
        if let Some(base_replacement_history) = replay_state.base_replacement_history {
            history.replace(base_replacement_history.to_vec());
        }
        // Materialize exact history semantics from the replay-derived suffix. The eventual lazy
        // design should keep this same replay shape, but drive it from a resumable reverse source
        // instead of an eagerly loaded `&[RolloutItem]`.
        for item in replay_state.rollout_suffix {
            match item {
                RolloutItem::ResponseItem(response_item) => {
                    history.record_items(
                        std::iter::once(response_item),
                        turn_context.model_info.truncation_policy.into(),
                    );
                }
                RolloutItem::InterAgentCommunication(communication) => {
                    let response_item = communication.to_model_input_item();
                    history.record_items(
                        std::iter::once(&response_item),
                        turn_context.model_info.truncation_policy.into(),
                    );
                }
                RolloutItem::InterAgentCommunicationMetadata { .. } => {}
                RolloutItem::Compacted(compacted) => {
                    if let Some(replacement_history) = &compacted.replacement_history {
                        // This should actually never happen, because the reverse loop above (to build rollout_suffix)
                        // should stop before any compaction that has Some replacement_history
                        history.replace(replacement_history.clone());
                    } else {
                        saw_legacy_compaction_without_replacement_history = true;
                        // Legacy rollouts without `replacement_history` should rebuild the
                        // historical TurnContext at the correct insertion point from persisted
                        // `TurnContextItem`s. These are rare enough that we currently just clear
                        // `reference_context_item`, reinject canonical context at the end of the
                        // resumed conversation, and accept the temporary out-of-distribution
                        // prompt shape.
                        // TODO(ccunningham): if we drop support for None replacement_history compaction items,
                        // we can get rid of this second loop entirely and just build `history` directly in the first loop.
                        let user_messages = compact::collect_user_messages(history.raw_items());
                        let rebuilt = compact::build_compacted_history(
                            Vec::new(),
                            &user_messages,
                            &compacted.message,
                        );
                        history.replace(rebuilt);
                    }
                }
                RolloutItem::EventMsg(EventMsg::ThreadRolledBack(rollback)) => {
                    history.drop_last_n_user_turns(rollback.num_turns);
                }
                RolloutItem::EventMsg(_)
                | RolloutItem::TurnContext(_)
                | RolloutItem::WorldState(_)
                | RolloutItem::SessionMeta(_) => {}
            }
        }

        let reference_context_item = match replay_state.reference_context_item {
            TurnReferenceContextItem::NeverSet | TurnReferenceContextItem::Cleared => None,
            TurnReferenceContextItem::Latest(turn_reference_context_item) => {
                Some(*turn_reference_context_item)
            }
        };
        let reference_context_item = if saw_legacy_compaction_without_replacement_history {
            None
        } else {
            reference_context_item
        };

        // Segments and their contents were collected newest-first; replay the surviving records
        // chronologically so compaction resets and merge patches have their original meaning.
        replay_state.world_state_replay.reverse();
        let mut world_state_baseline: Option<WorldStateSnapshot> = None;
        for item in replay_state.world_state_replay {
            match item {
                RolloutItem::Compacted(_) => world_state_baseline = None,
                RolloutItem::WorldState(world_state) if world_state.full => {
                    world_state_baseline = match serde_json::from_value(world_state.state.clone()) {
                        Ok(snapshot) => Some(snapshot),
                        Err(err) => {
                            tracing::warn!(%err, "failed to restore world-state snapshot");
                            None
                        }
                    };
                }
                RolloutItem::WorldState(world_state) => {
                    let Some(baseline) = world_state_baseline.as_mut() else {
                        tracing::warn!("ignored world-state patch without a full snapshot");
                        continue;
                    };
                    if let Err(err) = baseline.apply_merge_patch(&world_state.state) {
                        tracing::warn!(%err, "failed to apply world-state patch");
                        world_state_baseline = None;
                    }
                }
                RolloutItem::SessionMeta(_)
                | RolloutItem::ResponseItem(_)
                | RolloutItem::InterAgentCommunication(_)
                | RolloutItem::InterAgentCommunicationMetadata { .. }
                | RolloutItem::TurnContext(_)
                | RolloutItem::EventMsg(_) => {
                    unreachable!("only world-state replay items are collected")
                }
            }
        }

        let window = replay_state
            .window
            .or(initial_window)
            .unwrap_or(ReconstructedWindow {
                number: fallback_window_number,
                first_id: None,
                previous_id: None,
                id: None,
            });
        RolloutReconstruction {
            history: history.into_raw_items(),
            previous_turn_settings: replay_state.previous_turn_settings,
            reference_context_item,
            world_state_baseline,
            window_number: window.number,
            first_window_id: window.first_id,
            previous_window_id: window.previous_id,
            window_id: window.id,
        }
    }
}

#[derive(Default)]
struct ReplaySegment {
    items: Vec<RolloutItem>,
    counts_as_user_turn: bool,
}

fn drop_last_n_user_turns_from_response_items(
    items: &[ResponseItem],
    num_turns: usize,
) -> Vec<ResponseItem> {
    let mut history = ContextManager::new();
    history.replace(items.to_vec());
    history.drop_last_n_user_turns(u32::try_from(num_turns).unwrap_or(u32::MAX));
    history.raw_items().to_vec()
}

fn latest_compaction_position(segments: &[ReplaySegment]) -> Option<(usize, usize)> {
    segments
        .iter()
        .enumerate()
        .rev()
        .find_map(|(segment_idx, segment)| {
            segment
                .items
                .iter()
                .enumerate()
                .rev()
                .find_map(|(item_idx, item)| {
                    matches!(
                        item,
                        RolloutItem::Compacted(CompactedItem {
                            replacement_history: Some(_),
                            ..
                        })
                    )
                    .then_some((segment_idx, item_idx))
                })
        })
}

fn apply_rollback_to_compaction_segment(
    segments: &mut Vec<ReplaySegment>,
    segment_idx: usize,
    item_idx: usize,
    num_turns: usize,
) {
    if num_turns > 0
        && let RolloutItem::Compacted(CompactedItem {
            replacement_history: Some(replacement_history),
            ..
        }) = &segments[segment_idx].items[item_idx]
    {
        let adjusted_history =
            drop_last_n_user_turns_from_response_items(replacement_history, num_turns);
        if let RolloutItem::Compacted(compacted) = &mut segments[segment_idx].items[item_idx] {
            compacted.replacement_history = Some(adjusted_history);
        }
    }

    segments.truncate(segment_idx + 1);
}

fn apply_thread_rollback_to_segments(segments: &mut Vec<ReplaySegment>, num_turns: usize) {
    if num_turns == 0 {
        return;
    }

    let user_positions = segments
        .iter()
        .enumerate()
        .filter_map(|(idx, segment)| segment.counts_as_user_turn.then_some(idx))
        .collect::<Vec<_>>();
    if num_turns < user_positions.len() {
        let cut_idx = user_positions[user_positions.len() - num_turns];
        segments.truncate(cut_idx);
        return;
    }

    if let Some((compaction_segment_idx, compaction_item_idx)) =
        latest_compaction_position(segments)
    {
        let user_positions_after_compaction = segments
            .iter()
            .enumerate()
            .skip(compaction_segment_idx + 1)
            .filter_map(|(idx, segment)| segment.counts_as_user_turn.then_some(idx))
            .collect::<Vec<_>>();
        if num_turns <= user_positions_after_compaction.len() {
            let cut_idx =
                user_positions_after_compaction[user_positions_after_compaction.len() - num_turns];
            segments.truncate(cut_idx);
        } else {
            apply_rollback_to_compaction_segment(
                segments,
                compaction_segment_idx,
                compaction_item_idx,
                num_turns - user_positions_after_compaction.len(),
            );
        }
        return;
    }

    segments.clear();
}

fn rollout_items_after_thread_rollbacks(rollout_items: &[RolloutItem]) -> Vec<RolloutItem> {
    let mut segments = Vec::<ReplaySegment>::new();
    let mut active_segment = ReplaySegment::default();

    for item in rollout_items {
        if matches!(item, RolloutItem::EventMsg(EventMsg::TurnStarted(_)))
            && !active_segment.items.is_empty()
        {
            segments.push(active_segment);
            active_segment = ReplaySegment::default();
        }

        match item {
            RolloutItem::EventMsg(EventMsg::ThreadRolledBack(rollback)) => {
                if !active_segment.items.is_empty() {
                    segments.push(active_segment);
                    active_segment = ReplaySegment::default();
                }

                apply_thread_rollback_to_segments(
                    &mut segments,
                    usize::try_from(rollback.num_turns).unwrap_or(usize::MAX),
                );
            }
            RolloutItem::EventMsg(EventMsg::UserMessage(_)) => {
                active_segment.counts_as_user_turn = true;
                active_segment.items.push(item.clone());
            }
            RolloutItem::ResponseItem(response_item) => {
                active_segment.counts_as_user_turn |= is_user_turn_boundary(response_item);
                active_segment.items.push(item.clone());
            }
            RolloutItem::InterAgentCommunication(_) => {
                active_segment.counts_as_user_turn = true;
                active_segment.items.push(item.clone());
            }
            RolloutItem::InterAgentCommunicationMetadata { .. } => {
                active_segment.counts_as_user_turn = true;
                active_segment.items.push(item.clone());
            }
            RolloutItem::SessionMeta(_)
            | RolloutItem::TurnContext(_)
            | RolloutItem::WorldState(_)
            | RolloutItem::Compacted(_)
            | RolloutItem::EventMsg(_) => {
                active_segment.items.push(item.clone());
            }
        }
    }

    if !active_segment.items.is_empty() {
        segments.push(active_segment);
    }

    segments
        .into_iter()
        .flat_map(|segment| segment.items)
        .collect()
}

fn parse_uuid_v7(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value)
        .ok()
        .filter(|uuid| uuid.get_version_num() == 7)
}

fn reconstructed_window_from_session_context_window(
    context_window: &SessionContextWindow,
) -> Option<ReconstructedWindow> {
    let id = parse_uuid_v7(&context_window.window_id)?;
    Some(ReconstructedWindow {
        number: 0,
        first_id: Some(id),
        previous_id: None,
        id: Some(id),
    })
}
