/// Entry in the supervisor's diagnostic history exported by Rust wire fixtures.
struct ChannelHistoryEvent: Decodable {
    let producer_boot_id: String
    let event_seq: UInt64
    let family_state: FamilyChannelMonitorState
}
