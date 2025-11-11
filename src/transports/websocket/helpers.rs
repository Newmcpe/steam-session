use super::{Error, CmListError, WebSocketCMTransport, CmListCache};
use super::response::ApiResponseBody;
use crate::net::ApiRequest;
use crate::authentication_client::Error as AuthenticationClientError;
use crate::transports::Socks5ProxyConfig;
use std::sync::Arc;
use futures::StreamExt;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_tungstenite::tungstenite::http::uri::Uri;
use tokio_tungstenite::tungstenite::http::request::Request;
use tokio_tungstenite::{connect_async, client_async_tls_with_config, MaybeTlsStream};
use tokio_socks::tcp::Socks5Stream;

/// Generate a random key for the `Sec-WebSocket-Key` header.
fn generate_key() -> String {
    // a base64-encoded (see Section 4 of [RFC4648]) value that,
    // when decoded, is 16 bytes in length (RFC 6455)
    let r: [u8; 16] = rand::random();
    data_encoding::BASE64.encode(&r)
}

pub async fn connect_to_cm(cm_list: &Arc<tokio::sync::Mutex<CmListCache>>) -> Result<WebSocketCMTransport, Error> {
    connect_to_cm_with_socks5_proxy(cm_list, None).await
}

pub async fn connect_to_cm_with_socks5_proxy(
    cm_list: &Arc<tokio::sync::Mutex<CmListCache>>,
    proxy: Option<&Socks5ProxyConfig>,
) -> Result<WebSocketCMTransport, Error> {
    let proxied_client = if let Some(config) = proxy {
        Some(
            config
                .build_reqwest_client()
                .map_err(|err| Error::ProxyConfig(err.to_string()))?,
        )
    } else {
        None
    };

    let cm_server = {
        let mut cm_list = cm_list.lock().await;

        if let Some(client) = proxied_client.as_ref() {
            cm_list.update_with_client(client).await?;
        } else {
            cm_list.update().await?;
        }
        // pick a random server
        cm_list.pick_random_websocket_server()
    }
    .ok_or(Error::CmServer(CmListError::NoCmServer))?;
    let connect_addr = format!("wss://{}/cmsocket/", cm_server.endpoint);
    let uri = connect_addr.parse::<Uri>()?;
    let authority = uri.authority().ok_or(Error::UrlNoHostName)?.as_str();
    let host = authority
        .find('@')
        .map(|idx| authority.split_at(idx + 1).1)
        .unwrap_or_else(|| authority);
    let request_uri = uri.clone(); // Clone uri here
    let request = Request::builder()
        .header("batch-test", "true")
        .header("Host", host)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key())
        .uri(request_uri)
        .body(())?;
    // todo use timeout when connecting
    // let connect_timeout = Duration::seconds(CONNECTION_TIMEOUT_SECONDS);
    let (ws_stream, _) = if let Some(proxy_config) = proxy {
        let host = uri.host().ok_or(Error::UrlNoHostName)?;
        let port = uri.port_u16().unwrap_or(443);
        let proxy_addr = proxy_config.proxy_addr();
        let (username, password) = proxy_config.credentials();

        let stream = match (username, password) {
            (Some(user), Some(pass)) => {
                Socks5Stream::connect_with_password(proxy_addr, (host, port), user, pass).await?
            }
            (Some(_), None) | (None, Some(_)) => {
                return Err(Error::ProxyConfig(
                    "SOCKS5 proxy auth requires both username and password".into(),
                ));
            }
            _ => Socks5Stream::connect(proxy_addr, (host, port)).await?,
        }
        .into_inner();

        client_async_tls_with_config(request, stream, None, None).await?
    } else {
        connect_async(request).await?
    };
    let (ws_write, ws_read) = ws_stream.split();
    let transport = WebSocketCMTransport::new(ws_read, ws_write);

    Ok(transport)
}

pub async fn wait_for_response<Msg>(
    rx: oneshot::Receiver<Result<ApiResponseBody, Error>>,
) -> Result<Msg::Response, AuthenticationClientError>
where
    Msg: ApiRequest,
    <Msg as ApiRequest>::Response: Send,
{
    match timeout(std::time::Duration::from_secs(5), rx).await {
        Ok(response) => {
            let body = response??;
            let response = body.into_response::<Msg>()?;
            
            Ok(response)
        },
        Err(_error) => {
            log::debug!("Timed out waiting for response from {}", <Msg as ApiRequest>::NAME);
            Err(Error::Timeout.into())
        },
    }
}