mod base;
mod parser;

pub mod packet;

pub use self::base::CRLF;
pub use self::base::HEX_SIZE;
pub use self::parser::parse_and_authenticate;

use crate::protocol::common::addr::IpAddress;
use crate::protocol::common::{request::InboundRequest, stream::StandardTcpStream};

use log::error;
use std::io::ErrorKind;
use std::io::Result;
use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Helper function to accept an abstract TCP stream to Trojan connection
pub async fn accept<T: AsyncRead + AsyncWrite + Unpin + Send>(
    mut stream: StandardTcpStream<T>,
    secret: &[u8],
) -> Result<(InboundRequest, StandardTcpStream<T>)> {
    // Read trojan request header and generate request header
    match parse_and_authenticate(&mut stream, secret).await {
        Ok(request) => Ok((request.into_request(), stream)),
        Err(e) if e.kind() == ErrorKind::InvalidData => {
            let response = "HTTP/1.1 301 Moved Permanently\r\n\
                            Location: https://www.baidu.com\r\n\
                            Content-Length: 0\r\n\
                            \r\n";
            if let Err(e) = stream.write_all(response.as_bytes()).await {
                error!("Failed to send response: {}", e);
            }
            Err(e)
        }
        Err(e) => Err(e),
    }
}

/// Helper function to establish Trojan connection to remote server
pub async fn handshake<T: AsyncWrite + Unpin>(
    stream: &mut T,
    request: &InboundRequest,
    secret: &[u8],
) -> Result<()> {
    // Write request header
    stream.write_all(secret).await?;
    stream.write_u16(CRLF).await?;
    stream.write_u8(request.command as u8).await?;
    stream.write_u8(request.atype as u8).await?;
    match &request.addr_port.ip {
        IpAddress::IpAddr(IpAddr::V4(ipv4)) => {
            stream.write_all(&ipv4.octets()).await?;
        }
        IpAddress::IpAddr(IpAddr::V6(ipv6)) => {
            stream.write_all(&ipv6.octets()).await?;
        }
        IpAddress::Domain(domain) => {
            stream.write_u8(domain.as_bytes().len() as u8).await?;
            stream.write_all(&domain.as_bytes()).await?;
        }
    }
    stream.write_u16(request.addr_port.port).await?;
    stream.write_u16(CRLF).await?;
    stream.flush().await?;

    Ok(())
}
