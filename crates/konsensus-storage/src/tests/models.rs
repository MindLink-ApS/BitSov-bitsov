use super::*;

fn dummy_node_id() -> NodeId {
    let identity = konsensus_core::identity::NodeIdentity::from_mnemonic(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "",
    )
    .unwrap();
    *identity.node_id()
}

#[test]
fn room_new_has_unique_id() {
    let id = dummy_node_id();
    let r1 = Room::new("room-a".into(), id);
    let r2 = Room::new("room-b".into(), id);
    assert_ne!(r1.id, r2.id);
}

#[test]
fn room_new_sets_name_and_creator() {
    let id = dummy_node_id();
    let room = Room::new("test-room".into(), id);
    assert_eq!(room.name, "test-room");
    assert_eq!(room.created_by, id);
}

#[test]
fn room_new_metadata_is_empty_object() {
    let room = Room::new("m".into(), dummy_node_id());
    assert!(room.metadata.is_object());
    assert_eq!(room.metadata.as_object().unwrap().len(), 0);
}

#[test]
fn room_new_created_at_is_rfc3339() {
    let room = Room::new("t".into(), dummy_node_id());
    // Should parse as a valid RFC 3339 date
    assert!(chrono::DateTime::parse_from_rfc3339(&room.created_at).is_ok());
}

#[test]
fn room_serde_roundtrip() {
    let room = Room::new("serde-test".into(), dummy_node_id());
    let json = serde_json::to_string(&room).unwrap();
    let deserialized: Room = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.name, room.name);
    assert_eq!(deserialized.id, room.id);
}

#[test]
fn peer_new_defaults() {
    let id = dummy_node_id();
    let peer = Peer::new(id);
    assert_eq!(peer.node_id, id);
    assert!(peer.address.is_none());
    assert!(peer.last_seen.is_none());
    assert!(peer.display_name.is_none());
    assert!(peer.metadata.is_object());
}

#[test]
fn peer_serde_roundtrip() {
    let mut peer = Peer::new(dummy_node_id());
    peer.address = Some("10.0.0.1:9735".into());
    peer.display_name = Some("Alice".into());
    let json = serde_json::to_string(&peer).unwrap();
    let deserialized: Peer = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized.address.as_deref(), Some("10.0.0.1:9735"));
    assert_eq!(deserialized.display_name.as_deref(), Some("Alice"));
}

#[test]
fn file_metadata_from_file_record() {
    let record = FileRecord {
        id: "test-id".into(),
        filename: "doc.pdf".into(),
        mime_type: "application/pdf".into(),
        size_bytes: 12345,
        blake3_hash: "ab".repeat(32),
        sender: "cc".repeat(32),
        message_id: Some("dd".repeat(32)),
        data: vec![1, 2, 3],
        created_at: "2026-03-30T00:00:00Z".into(),
    };

    let meta = FileMetadata::from(&record);
    assert_eq!(meta.id, record.id);
    assert_eq!(meta.filename, record.filename);
    assert_eq!(meta.mime_type, record.mime_type);
    assert_eq!(meta.size_bytes, record.size_bytes);
    assert_eq!(meta.blake3_hash, record.blake3_hash);
    assert_eq!(meta.sender, record.sender);
    assert_eq!(meta.message_id, record.message_id);
    assert_eq!(meta.created_at, record.created_at);
}

#[test]
fn file_metadata_from_record_without_message_id() {
    let record = FileRecord {
        id: "no-msg".into(),
        filename: "photo.jpg".into(),
        mime_type: "image/jpeg".into(),
        size_bytes: 0,
        blake3_hash: "00".repeat(32),
        sender: "ff".repeat(32),
        message_id: None,
        data: vec![],
        created_at: "2026-01-01T00:00:00Z".into(),
    };

    let meta = FileMetadata::from(&record);
    assert!(meta.message_id.is_none());
}

#[test]
fn file_record_data_not_serialized() {
    let record = FileRecord {
        id: "skip-data".into(),
        filename: "test.bin".into(),
        mime_type: "application/octet-stream".into(),
        size_bytes: 3,
        blake3_hash: "11".repeat(32),
        sender: "22".repeat(32),
        message_id: None,
        data: vec![0xDE, 0xAD, 0xBE],
        created_at: "2026-01-01T00:00:00Z".into(),
    };

    let json = serde_json::to_string(&record).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    // data field is marked skip_serializing so should not appear as a key
    assert!(parsed.get("data").is_none());
    // The raw bytes should not be present in serialized form
    assert!(!json.contains("[222,173,190]"));
}

#[test]
fn file_record_serde_deserialize_with_data() {
    // data field is skip_serializing but still expected on deserialize
    let json = r#"{
        "id": "deser-test",
        "filename": "test.txt",
        "mime_type": "text/plain",
        "size_bytes": 100,
        "blake3_hash": "aabb",
        "sender": "ccdd",
        "message_id": null,
        "data": [1, 2, 3],
        "created_at": "2026-01-01T00:00:00Z"
    }"#;
    let record: FileRecord = serde_json::from_str(json).unwrap();
    assert_eq!(record.id, "deser-test");
    assert_eq!(record.data, vec![1, 2, 3]);
}

#[test]
fn file_metadata_serde_roundtrip() {
    let meta = FileMetadata {
        id: "meta-test".into(),
        filename: "report.pdf".into(),
        mime_type: "application/pdf".into(),
        size_bytes: 5000,
        blake3_hash: "ee".repeat(32),
        sender: "ff".repeat(32),
        message_id: Some("00".repeat(32)),
        created_at: "2026-06-15T12:00:00Z".into(),
    };
    let json = serde_json::to_string(&meta).unwrap();
    let deser: FileMetadata = serde_json::from_str(&json).unwrap();
    assert_eq!(deser.id, meta.id);
    assert_eq!(deser.filename, meta.filename);
    assert_eq!(deser.size_bytes, meta.size_bytes);
}
