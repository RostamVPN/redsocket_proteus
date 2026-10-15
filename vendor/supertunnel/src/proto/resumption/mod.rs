//! Session resumption protocol module.
//!
//! Provides the handshake and state management required to seamlessly reconnect
//! dropped streams without tearing down the logical session.

mod client;
mod codec;
mod message;
mod server;

pub use client::{ResumptionClient, ResumptionHandle};
pub use codec::ResumptionCodec;
use message::{Command, ResumptionMessage};
pub use server::{ResumptionMap, ResumptionServer};

#[cfg(test)]
pub mod tests {
    use tokio_test::assert_ok;

    use crate::proto::resumption::{ResumptionClient, ResumptionServer};
    use crate::test::{TestIoProtocol, TestNetwork, TestPayload};

    #[tokio::test]
    async fn valid_io_flow() {
        for (c_io, s_io, len) in TestPayload::iter() {
            let client = ResumptionClient::new(TestIoProtocol::from_mock(c_io));
            let server = ResumptionServer::new(TestIoProtocol::from_mock(s_io));

            let network = TestNetwork::new(client, server);
            let (c_to_s_result, s_to_c_result) = network.run().await;

            assert_ok!(c_to_s_result);
            assert_ok!(s_to_c_result);
            assert!(c_to_s_result.unwrap() >= len);
            assert!(s_to_c_result.unwrap() >= len);
        }
    }
}
