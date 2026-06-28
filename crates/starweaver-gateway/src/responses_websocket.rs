use std::time::Duration;

use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use http::{HeaderMap, header};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};

use crate::error::{GatewayError, Result};

const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

type UpstreamWebSocketStream = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug)]
pub enum UpstreamResponsesMessage {
    Text(String),
    Close,
}

pub struct UpstreamResponsesWebSocket {
    sender: SplitSink<UpstreamWebSocketStream, Message>,
    receiver: SplitStream<UpstreamWebSocketStream>,
}

impl UpstreamResponsesWebSocket {
    pub(crate) async fn connect(url: &str, headers: &HeaderMap) -> Result<Self> {
        let mut request = url
            .into_client_request()
            .map_err(|error| GatewayError::BadRequest {
                message: format!("invalid upstream websocket request: {error}"),
            })?;
        for (name, value) in headers {
            if websocket_handshake_header_is_gateway_owned(name.as_str())
                || *name == header::CONTENT_TYPE
                || *name == header::CONTENT_LENGTH
            {
                continue;
            }
            request.headers_mut().insert(name.clone(), value.clone());
        }

        let (stream, _) = tokio::time::timeout(UPSTREAM_CONNECT_TIMEOUT, connect_async(request))
            .await
            .map_err(|_| GatewayError::Upstream {
                reason: "responses_websocket_connect_timeout",
            })?
            .map_err(|_| GatewayError::Upstream {
                reason: "responses_websocket_connect_failed",
            })?;
        let (sender, receiver) = stream.split();
        Ok(Self { sender, receiver })
    }

    pub(crate) async fn send_text(&mut self, text: String) -> Result<()> {
        self.sender
            .send(Message::Text(text.into()))
            .await
            .map_err(|_| GatewayError::Upstream {
                reason: "responses_websocket_send_failed",
            })
    }

    pub(crate) async fn next_message(&mut self) -> Result<Option<UpstreamResponsesMessage>> {
        while let Some(message) = self.receiver.next().await {
            let message = message.map_err(|_| GatewayError::Upstream {
                reason: "responses_websocket_receive_failed",
            })?;
            match message {
                Message::Text(text) => {
                    return Ok(Some(UpstreamResponsesMessage::Text(text.to_string())));
                }
                Message::Ping(payload) => {
                    self.sender
                        .send(Message::Pong(payload))
                        .await
                        .map_err(|_| GatewayError::Upstream {
                            reason: "responses_websocket_pong_failed",
                        })?;
                }
                Message::Pong(_) | Message::Frame(_) => {}
                Message::Close(_) => return Ok(Some(UpstreamResponsesMessage::Close)),
                Message::Binary(_) => {
                    return Err(GatewayError::Upstream {
                        reason: "responses_websocket_binary_frame",
                    });
                }
            }
        }
        Ok(None)
    }

    pub(crate) async fn close(&mut self) {
        let _ = self.sender.send(Message::Close(None)).await;
    }
}

pub fn http_url_to_ws_url(url: &str) -> Result<String> {
    match url.split_once("://") {
        Some(("https", rest)) => Ok(format!("wss://{rest}")),
        Some(("http", rest)) => Ok(format!("ws://{rest}")),
        _ => Err(GatewayError::BadRequest {
            message: format!("responses websocket upstream URL must use http or https: {url}"),
        }),
    }
}

const fn websocket_handshake_header_is_gateway_owned(name: &str) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("upgrade")
        || name.eq_ignore_ascii_case("sec-websocket-accept")
        || name.eq_ignore_ascii_case("sec-websocket-key")
        || name.eq_ignore_ascii_case("sec-websocket-protocol")
        || name.eq_ignore_ascii_case("sec-websocket-version")
}

#[cfg(test)]
mod tests {
    use super::http_url_to_ws_url;

    #[test]
    fn http_url_to_ws_url_converts_https() {
        assert_eq!(
            http_url_to_ws_url("https://api.openai.example/v1/responses")
                .unwrap_or_else(|error| panic!("https URL should convert: {error}")),
            "wss://api.openai.example/v1/responses"
        );
    }

    #[test]
    fn http_url_to_ws_url_converts_http() {
        assert_eq!(
            http_url_to_ws_url("http://127.0.0.1:8080/v1/responses")
                .unwrap_or_else(|error| panic!("http URL should convert: {error}")),
            "ws://127.0.0.1:8080/v1/responses"
        );
    }

    #[test]
    fn http_url_to_ws_url_rejects_other_schemes() {
        assert!(http_url_to_ws_url("ftp://api.openai.example/v1/responses").is_err());
    }
}
