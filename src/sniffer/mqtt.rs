/*
 * mqtt.rs
 *
 * Purpose:
 *     Provides MQTT packet parsing helpers
 *     for the WARDEN sniffer subsystem.
 *
 * Responsibilities:
 *     - Parse MQTT control packet types
 *     - Convert raw payloads into MessageType values
 *     - Normalize MQTT protocol metadata
 *
 * Non-Responsibilities:
 *     - TCP packet capture
 *     - IDS detection analysis
 *     - Mitigation
 *     - Blockchain anchoring
 *
 * Architecture:
 *
 *      Raw TCP Payload
 *              ↓
 *        MQTT Parsing
 *              ↓
 *        MessageType
 */

/* -------------------------------------------------------------------------- */
/*                                 Imports                                    */
/* -------------------------------------------------------------------------- */

use crate::types::MessageType;

/* -------------------------------------------------------------------------- */
/*                            MQTT Parsing                                    */
/* -------------------------------------------------------------------------- */

/**
 * Parses MQTT control packet type from raw TCP payload.
 *
 * MQTT stores the control packet type
 * in the upper nibble of byte 0.
 *
 * # Arguments
 *
 * * `payload` - Raw MQTT TCP payload
 */
pub fn parse_mqtt_type(
    payload: &[u8]
) -> MessageType {
    if payload.len() < 2 {
        return MessageType::Unknown;
    }

    let msg_type_nibble =
        (payload[0] >> 4) & 0x0F;

    let name = match msg_type_nibble {
        1 => "CONNECT",
        2 => "CONNACK",
        3 => "PUBLISH",
        4 => "PUBACK",
        5 => "PUBREC",
        6 => "PUBREL",
        7 => "PUBCOMP",
        8 => "SUBSCRIBE",
        9 => "SUBACK",
        10 => "UNSUBSCRIBE",
        11 => "UNSUBACK",
        12 => "PINGREQ",
        13 => "PINGRESP",
        14 => "DISCONNECT",
        15 => "AUTH",

        _ => {
            return MessageType::Known(
                format!(
                    "MQTT_TYPE_{msg_type_nibble}"
                )
            )
        }
    };

    MessageType::Known(name.to_string())
}

/* -------------------------------------------------------------------------- */
/*                                   Tests                                    */
/* -------------------------------------------------------------------------- */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_publish() {
        let payload = [0x30, 0x00];

        assert_eq!(
            parse_mqtt_type(&payload),

            MessageType::Known(
                "PUBLISH".to_string()
            )
        );
    }

    #[test]
    fn parses_connect() {
        let payload = [0x10, 0x00];

        assert_eq!(
            parse_mqtt_type(&payload),

            MessageType::Known(
                "CONNECT".to_string()
            )
        );
    }

    #[test]
    fn handles_short_payload() {
        assert_eq!(
            parse_mqtt_type(&[0x30]),

            MessageType::Unknown
        );
    }
}