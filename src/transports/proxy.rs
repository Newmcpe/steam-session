pub use self::config::{Socks5ProxyConfig, Socks5ProxyConfigError};

mod config {
    use std::fmt;
    use std::str::FromStr;

    use reqwest::Client;
    use url::Url;

    /// SOCKS5 proxy configuration.
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    pub struct Socks5ProxyConfig {
        host: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        /// `true` означает, что DNS будет резолвиться на стороне прокси (`socks5h`).
        remote_dns: bool,
    }

    impl Socks5ProxyConfig {
        /// Creates configuration based on host/port.
        pub fn new(host: impl Into<String>, port: u16) -> Self {
            Self {
                host: host.into(),
                port,
                username: None,
                password: None,
                remote_dns: true,
            }
        }

        /// Controls whether DNS should be resolved by the proxy (`socks5h`).
        pub fn with_remote_dns(mut self, remote_dns: bool) -> Self {
            self.remote_dns = remote_dns;
            self
        }

        /// Adds credentials.
        pub fn with_credentials(
            mut self,
            username: impl Into<String>,
            password: impl Into<String>,
        ) -> Self {
            self.username = Some(username.into());
            self.password = Some(password.into());
            self
        }

        /// Returns proxy host.
        pub fn host(&self) -> &str {
            &self.host
        }

        /// Returns proxy port.
        pub fn port(&self) -> u16 {
            self.port
        }

        /// Returns username/password pair.
        pub fn credentials(&self) -> (Option<&str>, Option<&str>) {
            (
                self.username.as_deref().filter(|value| !value.is_empty()),
                self.password.as_deref(),
            )
        }

        /// Whether DNS should be resolved remotely.
        pub fn remote_dns(&self) -> bool {
            self.remote_dns
        }

        /// Builds `socks5[h]://user:pass@host:port` URL.
        pub fn proxy_url(&self) -> Result<Url, Socks5ProxyConfigError> {
            let scheme = if self.remote_dns { "socks5h" } else { "socks5" };
            let mut url = Url::parse(&format!("{scheme}://{}:{}", self.host, self.port))
                .map_err(Socks5ProxyConfigError::Url)?;

            if let Some(username) = &self.username {
                if !username.is_empty() && url.set_username(username).is_err() {
                    return Err(Socks5ProxyConfigError::InvalidUsername);
                }
            }

            if let Some(password) = &self.password {
                if url.set_password(Some(password)).is_err() {
                    return Err(Socks5ProxyConfigError::InvalidPassword);
                }
            }

            Ok(url)
        }

        /// Creates `reqwest::Client` configured with this SOCKS5 proxy.
        pub fn build_reqwest_client(&self) -> Result<Client, Socks5ProxyConfigError> {
            let url = self.proxy_url()?;
            let proxy =
                reqwest::Proxy::all(url.as_str()).map_err(Socks5ProxyConfigError::Reqwest)?;

            Client::builder()
                .proxy(proxy)
                .build()
                .map_err(Socks5ProxyConfigError::Reqwest)
        }

        /// Returns proxy address tuple for `tokio-socks`.
        pub fn proxy_addr(&self) -> (&str, u16) {
            (&self.host, self.port)
        }
    }

    impl FromStr for Socks5ProxyConfig {
        type Err = Socks5ProxyConfigError;

        fn from_str(value: &str) -> Result<Self, Self::Err> {
            let url = if value.starts_with("socks5") {
                Url::parse(value).map_err(Socks5ProxyConfigError::Url)?
            } else {
                Url::parse(&format!("socks5h://{value}")).map_err(Socks5ProxyConfigError::Url)?
            };

            let scheme = url.scheme();

            if scheme != "socks5" && scheme != "socks5h" {
                return Err(Socks5ProxyConfigError::UnsupportedScheme(scheme.into()));
            }

            let host = url
                .host_str()
                .ok_or(Socks5ProxyConfigError::MissingHost)?
                .to_string();
            let port = url.port().unwrap_or(1080);
            let username = match url.username() {
                "" => None,
                value => Some(value.to_string()),
            };
            let password = url.password().map(|value| value.to_string());
            let remote_dns = scheme == "socks5h";

            Ok(Socks5ProxyConfig {
                host,
                port,
                username,
                password,
                remote_dns,
            })
        }
    }

    impl fmt::Display for Socks5ProxyConfig {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let (username, _) = self.credentials();
            let scheme = if self.remote_dns { "socks5h" } else { "socks5" };

            if let Some(username) = username {
                write!(f, "{scheme}://{username}:***@{}:{}", self.host, self.port)
            } else {
                write!(f, "{scheme}://{}:{}", self.host, self.port)
            }
        }
    }

    /// SOCKS5 proxy configuration errors.
    #[derive(Debug, thiserror::Error)]
    pub enum Socks5ProxyConfigError {
        #[error("Invalid SOCKS5 proxy URL: {0}")]
        Url(#[from] url::ParseError),
        #[error("SOCKS5 proxy URL does not contain host")]
        MissingHost,
        #[error("Scheme {0} is not supported for SOCKS5 proxy URLs")]
        UnsupportedScheme(String),
        #[error("Invalid username for SOCKS5 proxy")]
        InvalidUsername,
        #[error("Invalid password for SOCKS5 proxy")]
        InvalidPassword,
        #[error("Failed to build HTTP client with SOCKS5 proxy: {0}")]
        Reqwest(#[from] reqwest::Error),
    }
}
