use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;

pub trait MessageTag: Serialize + DeserializeOwned {
    const TAG: u8;
}

#[derive(Debug, Clone)]
pub enum MessageError {
    Serialization(String),
    Deserialization(String),
    TagMismatch { expected: u8, found: u8 },
    NotFound { sender: u8 },
    InvalidFrame(String),
}

impl std::fmt::Display for MessageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialization(s) => write!(f, "serialization error: {s}"),
            Self::Deserialization(s) => write!(f, "deserialization error: {s}"),
            Self::TagMismatch { expected, found } => {
                write!(f, "tag mismatch: expected {expected:#04x}, found {found:#04x}")
            }
            Self::NotFound { sender } => write!(f, "message not found for sender {sender}"),
            Self::InvalidFrame(s) => write!(f, "invalid frame: {s}"),
        }
    }
}

impl std::error::Error for MessageError {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PhaseOutput {
    pub broadcasts: Vec<Vec<u8>>,
    pub p2p: BTreeMap<u8, Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PhaseInput {
    pub broadcasts: BTreeMap<u8, Vec<u8>>,
    pub p2p: BTreeMap<u8, Vec<u8>>,
}

const FRAME_HEADER_LEN: usize = 5; // 1 byte tag + 4 bytes length

fn encode_frame<T: MessageTag>(message: &T) -> Result<Vec<u8>, MessageError> {
    let payload =
        bincode::serialize(message).map_err(|e| MessageError::Serialization(e.to_string()))?;
    let len = u32::try_from(payload.len())
        .map_err(|_| MessageError::Serialization("payload exceeds u32::MAX".into()))?;
    let mut buf = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    buf.push(T::TAG);
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&payload);
    Ok(buf)
}

fn find_in_stream<T: MessageTag>(stream: &[u8]) -> Result<T, MessageError> {
    let mut offset = 0;
    while offset < stream.len() {
        if offset + FRAME_HEADER_LEN > stream.len() {
            return Err(MessageError::InvalidFrame("truncated header".into()));
        }
        let tag = stream[offset];
        let len = u32::from_be_bytes([
            stream[offset + 1],
            stream[offset + 2],
            stream[offset + 3],
            stream[offset + 4],
        ]) as usize;
        offset += FRAME_HEADER_LEN;
        if offset + len > stream.len() {
            return Err(MessageError::InvalidFrame("truncated payload".into()));
        }
        if tag == T::TAG {
            return bincode::deserialize(&stream[offset..offset + len])
                .map_err(|e| MessageError::Deserialization(e.to_string()));
        }
        offset += len;
    }
    // Tag never matched — caller wraps with the sender index.
    Err(MessageError::NotFound { sender: 0 })
}

impl PhaseOutput {
    #[must_use]
    pub fn new() -> Self {
        PhaseOutput {
            broadcasts: Vec::new(),
            p2p: BTreeMap::new(),
        }
    }

    pub fn add_broadcast<T: MessageTag>(
        &mut self,
        message: &T,
    ) -> Result<(), MessageError> {
        self.broadcasts.push(encode_frame(message)?);
        Ok(())
    }

    pub fn add_p2p<T: MessageTag>(
        &mut self,
        receiver: u8,
        message: &T,
    ) -> Result<(), MessageError> {
        self.p2p
            .entry(receiver)
            .or_default()
            .extend_from_slice(&encode_frame(message)?);
        Ok(())
    }
}

impl PhaseInput {
    pub fn get_broadcast<T: MessageTag>(&self, sender: u8) -> Result<T, MessageError> {
        let stream = self
            .broadcasts
            .get(&sender)
            .ok_or(MessageError::NotFound { sender })?;
        find_in_stream::<T>(stream).map_err(|e| match e {
            MessageError::NotFound { .. } => MessageError::NotFound { sender },
            other => other,
        })
    }

    pub fn get_p2p<T: MessageTag>(&self, sender: u8) -> Result<T, MessageError> {
        let stream = self
            .p2p
            .get(&sender)
            .ok_or(MessageError::NotFound { sender })?;
        find_in_stream::<T>(stream).map_err(|e| match e {
            MessageError::NotFound { .. } => MessageError::NotFound { sender },
            other => other,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    struct MsgA {
        value: u32,
    }

    impl MessageTag for MsgA {
        const TAG: u8 = 0xA0;
    }

    #[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
    struct MsgB {
        name: String,
    }

    impl MessageTag for MsgB {
        const TAG: u8 = 0xB0;
    }

    #[test]
    fn test_broadcast_round_trip() {
        let msg = MsgA { value: 42 };
        let mut output = PhaseOutput::new();
        output.add_broadcast(&msg).unwrap();

        // Simulate network: sender 1's broadcasts → receiver's input
        let mut input = PhaseInput {
            broadcasts: BTreeMap::new(),
            p2p: BTreeMap::new(),
        };
        for blob in &output.broadcasts {
            input
                .broadcasts
                .entry(1)
                .or_default()
                .extend_from_slice(blob);
        }

        let decoded: MsgA = input.get_broadcast(1).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_p2p_round_trip() {
        let msg = MsgA { value: 99 };
        let mut output = PhaseOutput::new();
        output.add_p2p(2, &msg).unwrap();

        // Simulate network: sender 1's p2p[2] → receiver 2's p2p[1]
        let mut input = PhaseInput {
            broadcasts: BTreeMap::new(),
            p2p: BTreeMap::new(),
        };
        input.p2p.insert(1, output.p2p[&2].clone());

        let decoded: MsgA = input.get_p2p(1).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_tag_mismatch() {
        let msg = MsgA { value: 1 };
        let mut output = PhaseOutput::new();
        output.add_broadcast(&msg).unwrap();

        let mut input = PhaseInput {
            broadcasts: BTreeMap::new(),
            p2p: BTreeMap::new(),
        };
        for blob in &output.broadcasts {
            input
                .broadcasts
                .entry(1)
                .or_default()
                .extend_from_slice(blob);
        }

        // Try to decode as MsgB — should fail with NotFound
        let result = input.get_broadcast::<MsgB>(1);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), MessageError::NotFound { sender: 1 }));
    }

    #[test]
    fn test_multiple_p2p_same_receiver() {
        let msg_a = MsgA { value: 7 };
        let msg_b = MsgB {
            name: "hello".into(),
        };

        let mut output = PhaseOutput::new();
        output.add_p2p(2, &msg_a).unwrap();
        output.add_p2p(2, &msg_b).unwrap();

        // Both frames are in the same byte stream for receiver 2
        let mut input = PhaseInput {
            broadcasts: BTreeMap::new(),
            p2p: BTreeMap::new(),
        };
        input.p2p.insert(1, output.p2p[&2].clone());

        let decoded_a: MsgA = input.get_p2p(1).unwrap();
        let decoded_b: MsgB = input.get_p2p(1).unwrap();
        assert_eq!(decoded_a, msg_a);
        assert_eq!(decoded_b, msg_b);
    }

    #[test]
    fn test_multiple_broadcasts_same_sender() {
        let msg_a = MsgA { value: 10 };
        let msg_b = MsgB {
            name: "world".into(),
        };

        let mut output = PhaseOutput::new();
        output.add_broadcast(&msg_a).unwrap();
        output.add_broadcast(&msg_b).unwrap();

        // Concatenate all broadcast blobs into one stream for sender 1
        let mut input = PhaseInput {
            broadcasts: BTreeMap::new(),
            p2p: BTreeMap::new(),
        };
        for blob in &output.broadcasts {
            input
                .broadcasts
                .entry(1)
                .or_default()
                .extend_from_slice(blob);
        }

        let decoded_a: MsgA = input.get_broadcast(1).unwrap();
        let decoded_b: MsgB = input.get_broadcast(1).unwrap();
        assert_eq!(decoded_a, msg_a);
        assert_eq!(decoded_b, msg_b);
    }

    #[test]
    fn test_missing_sender() {
        let input = PhaseInput {
            broadcasts: BTreeMap::new(),
            p2p: BTreeMap::new(),
        };

        let result = input.get_broadcast::<MsgA>(99);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MessageError::NotFound { sender: 99 }
        ));
    }

    #[test]
    fn test_truncated_frame() {
        let mut input = PhaseInput {
            broadcasts: BTreeMap::new(),
            p2p: BTreeMap::new(),
        };
        // Only 3 bytes — less than the 5-byte header
        input.broadcasts.insert(1, vec![0x00, 0x01, 0x02]);

        let result = input.get_broadcast::<MsgA>(1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MessageError::InvalidFrame(_)
        ));
    }

    #[test]
    fn test_truncated_payload() {
        let mut input = PhaseInput {
            broadcasts: BTreeMap::new(),
            p2p: BTreeMap::new(),
        };
        // Header says 100 bytes of payload but only 2 follow
        let mut buf = vec![0xA0];
        buf.extend_from_slice(&100u32.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0x01]);
        input.broadcasts.insert(1, buf);

        let result = input.get_broadcast::<MsgA>(1);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            MessageError::InvalidFrame(_)
        ));
    }
}
