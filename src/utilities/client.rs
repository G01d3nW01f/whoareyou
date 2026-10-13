use anyhow::{anyhow, Result};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use std::net::TcpStream;
use url::Url;

pub fn get_certificate(url: &str) -> Result<Vec<u8>> {
    let url = Url::parse(url)?;

    let host = url
        .host_str()
        .ok_or_else(|| anyhow!("host not found"))?;

    let port = url.port().unwrap_or(443);

    let addr = format!("{}:{}", host, port);

    let stream = TcpStream::connect(addr)?;

    let mut builder = SslConnector::builder(SslMethod::tls())?;

    // 証明書検証無効
    builder.set_verify(SslVerifyMode::NONE);

    let connector = builder.build();

    let ssl_stream = connector.connect(host, stream)?;

    let cert = ssl_stream
        .ssl()
        .peer_certificate()
        .ok_or_else(|| anyhow!("certificate not found"))?;

    Ok(cert.to_der()?)
}
