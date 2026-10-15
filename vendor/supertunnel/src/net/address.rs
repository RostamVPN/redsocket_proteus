//! Network addressing.
//!
//! Defines structures for representing and parsing network targets, including
//! domain names and IP addresses used for routing.

use std::fmt::Display;
use std::net::{IpAddr, SocketAddr};

/// Represents a destination network address and port.
///
/// Used by the routing layer to instruct the server where to establish outbound connections.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct NetworkTarget {
    /// The network address (IP or domain name).
    addr: NetworkAddress,
    /// The target network port.
    port: u16,
}

impl NetworkTarget {
    /// Creates a new `NetworkTarget`.
    ///
    /// # Inputs
    ///
    /// * `addr: NetworkAddress` - The network address (IP or domain name).
    /// * `port: u16` - The target network port.
    pub fn new(addr: NetworkAddress, port: u16) -> Self {
        Self { addr, port }
    }

    /// Returns a cloned copy of the `NetworkAddress`.
    pub fn addr(&self) -> NetworkAddress {
        self.addr.clone()
    }

    /// Returns the port number.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the addr as a string and the port number.
    ///
    /// The result can be used when needing a `tokio::net::ToSocketAddrs` arg.
    pub fn string_addr_port(&self) -> (String, u16) {
        (self.addr.clone().into(), self.port)
    }
}

impl From<SocketAddr> for NetworkTarget {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(socket_addr_v4) => NetworkTarget {
                addr: NetworkAddress::IpAddr(IpAddr::V4(*socket_addr_v4.ip())),
                port: socket_addr_v4.port(),
            },
            SocketAddr::V6(socket_addr_v6) => NetworkTarget {
                addr: NetworkAddress::IpAddr(IpAddr::V6(*socket_addr_v6.ip())),
                port: socket_addr_v6.port(),
            },
        }
    }
}

impl From<(String, u16)> for NetworkTarget {
    fn from((value, port): (String, u16)) -> Self {
        Self {
            addr: NetworkAddress::from(value),
            port,
        }
    }
}

impl Display for NetworkTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.addr, self.port)
    }
}

impl std::net::ToSocketAddrs for NetworkTarget {
    type Iter = std::vec::IntoIter<std::net::SocketAddr>;

    fn to_socket_addrs(&self) -> std::io::Result<Self::Iter> {
        match self.addr() {
            NetworkAddress::IpAddr(ip_addr) => (ip_addr, self.port())
                .to_socket_addrs()
                .map(|iter| iter.collect::<Vec<_>>().into_iter()),
            NetworkAddress::Name(name) => (name, self.port()).to_socket_addrs(),
        }
    }
}

/// Represents a parsed network address.
///
/// Can encapsulate either a direct IP address or a domain name that requires DNS resolution.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum NetworkAddress {
    IpAddr(IpAddr),
    Name(String),
}

impl From<String> for NetworkAddress {
    fn from(mut value: String) -> Self {
        if let Ok(ip_addr) = value.parse() {
            NetworkAddress::IpAddr(ip_addr)
        } else {
            value.truncate(u8::MAX as usize);
            NetworkAddress::Name(value)
        }
    }
}

impl From<NetworkAddress> for String {
    fn from(addr: NetworkAddress) -> Self {
        format!("{addr}")
    }
}

impl From<IpAddr> for NetworkAddress {
    fn from(addr: IpAddr) -> Self {
        NetworkAddress::IpAddr(addr)
    }
}

impl Display for NetworkAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkAddress::IpAddr(ip_addr) => write!(f, "{ip_addr}"),
            NetworkAddress::Name(s) => write!(f, "{s}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn check_from() {
        let addresses = vec![
            NetworkAddress::from(String::from("test.com")),
            NetworkAddress::from(IpAddr::V4(Ipv4Addr::new(4, 3, 2, 1))),
            NetworkAddress::from(IpAddr::V6(Ipv6Addr::new(8, 7, 6, 5, 4, 3, 2, 1))),
        ];

        for addr in addresses {
            let _target = NetworkTarget { addr, port: 12345 };
        }
    }

    fn check_name_len(addr: &NetworkAddress, expected_len: usize) {
        let NetworkAddress::Name(name) = addr else {
            panic!()
        };
        assert_eq!(name.len(), expected_len);
    }

    #[test]
    fn max_name_length() {
        let addr = NetworkAddress::from("a".repeat(255));
        check_name_len(&addr, 255);
    }

    #[test]
    fn name_too_long() {
        // Long names are truncated to 255 bytes
        for len in [256, 257, 258, 300, 1000] {
            let addr = NetworkAddress::from("a".repeat(len));
            check_name_len(&addr, 255);
        }
    }
}
