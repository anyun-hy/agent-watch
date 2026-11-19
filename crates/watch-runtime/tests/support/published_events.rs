use claude_watch_core::channel::ChannelMonitorEvent;
use claude_watch_runtime::{channel_policy_status::read_frame_with_events, storage::StateStore};

pub fn after(store: &StateStore, sequence: u64) -> Vec<ChannelMonitorEvent> {
    let mut frame = read_frame_with_events(store);
    let mut events: Vec<ChannelMonitorEvent> = serde_json::from_value(frame["events"].take())
        .expect("supervisor must publish its bounded channel event history");
    events.retain(|event| event.event_seq > sequence);
    events
}
