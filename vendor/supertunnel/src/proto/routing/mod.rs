//! Routing and multiplexing protocol module.
//!
//! Handles multiplexing multiple independent logical sessions over a single
//! transport stream while routing incoming messages to their associated session.

mod client;
mod codec;
mod message;
mod server;

pub use client::{RoutingClient, RoutingError, RoutingHandle};
pub use codec::RoutingCodec;
use message::{Command, RoutingMessage};
pub use server::RoutingServer;

#[cfg(test)]
pub mod tests {
    use tokio_test::assert_ok;

    use crate::net::{NetworkAddress, NetworkTarget};
    use crate::proto::routing::{RoutingClient, RoutingServer};
    use crate::test::{TestConnector, TestIoProtocol, TestNetwork, TestPayload};
    use crate::util::EndMethod;

    #[tokio::test]
    async fn valid_io_flow() {
        // let _ = env_logger::try_init();
        for (c_io, s_io, len) in TestPayload::iter() {
            // Pre-load the server connector with the serverside io object. When
            // it gets a connect request from the client, it will return the
            // connections that we push onto it.
            let mut connector = TestConnector::new();
            connector.push(TestIoProtocol::from_mock(s_io)).await;

            // Create the client and server, the client is not going to resume.
            let server = RoutingServer::new(connector).await;
            let client = RoutingClient::new();
            let mut handle = client.handle().clone();

            // The client process is split into two. First you connect and wait
            // for the result, and then you add the session object. We will run
            // this part in the background, while concurrently driving the test
            // network io in the main task below.

            // Start up the network transfer process in the background.
            let network_handle = tokio::spawn(async move {
                let network = TestNetwork::new(client, server);
                network.run().await
            });

            // Now initiate the connection from the client. The server's test
            // connector will ignore the target, but we still need one.
            let name = String::from("mock_connection");
            let target = NetworkTarget::new(NetworkAddress::from(name), 0);

            // Send request and wait for server to reply.
            let session_id = assert_ok!(handle.connect_session(target, None).await);

            // Now add the client app data source to do the actual data transfer.
            let client_data = TestIoProtocol::from_mock(c_io).with_id(session_id);
            assert_ok!(handle.add_session(session_id, client_data).await);

            // The tunnel should close when this session is done.
            assert_ok!(handle.set_end_method(EndMethod::Empty).await);

            // Wait for the transfer to finish.
            let (c_to_s_result, s_to_c_result) = assert_ok!(network_handle.await);

            assert_ok!(c_to_s_result);
            assert_ok!(s_to_c_result);
            assert!(c_to_s_result.unwrap() >= len);
            assert!(s_to_c_result.unwrap() >= len);
        }
    }
}
