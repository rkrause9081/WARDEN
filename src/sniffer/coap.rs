//! CoAP parser helpers.

use crate::types::MessageType;

/// Parse CoAP method from raw UDP payload.
///
/// CoAP byte 1 is the Code field:
/// - upper 3 bits = class
/// - lower 5 bits = detail
///
/// Request methods are class 0:
/// - 0.01 GET
/// - 0.02 POST
/// - 0.03 PUT
/// - 0.04 DELETE
pub fn parse_coap_method(payload: &[u8]) -> MessageType {
    if payload.len() < 4 {
        return MessageType::Unknown;
    }

    let code = payload[1];
    let code_class = (code >> 5) & 0x07;
    let code_detail = code & 0x1F;

    if code_class == 0 {
        let name = match code_detail {
            1 => "GET",
            2 => "POST",
            3 => "PUT",
            4 => "DELETE",
            _ => return MessageType::Known(format!("COAP_CODE_0.{code_detail:02}")),
        };

        return MessageType::Known(name.to_string());
    }

    MessageType::Known(format!("COAP_{code_class}.{code_detail:02}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_get() {
        let payload = [0x40, 0x01, 0x00, 0x01];
        assert_eq!(
            parse_coap_method(&payload),
            MessageType::Known("GET".to_string())
        );
    }

    #[test]
    fn parses_post() {
        let payload = [0x40, 0x02, 0x00, 0x01];
        assert_eq!(
            parse_coap_method(&payload),
            MessageType::Known("POST".to_string())
        );
    }

    #[test]
    fn handles_short_payload() {
        assert_eq!(parse_coap_method(&[0x40, 0x01]), MessageType::Unknown);
    }
}
