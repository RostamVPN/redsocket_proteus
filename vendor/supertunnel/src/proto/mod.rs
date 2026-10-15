//! Core [`crate::Protocol`] trait implementations and definitions.
//!
//! Defines the core [`crate::Protocol`] protocol implementations that can be combined
//! to form a concrete, usable SuperTunnel network stack.

use crate::{FrameSize, Protocol};

pub mod framing;
pub mod payload;
pub mod reliability;
pub mod resumption;
pub mod routing;

pub use framing::{Framing, FramingCodec};
pub use payload::{Payload, PayloadCodec, TcpPayload, TcpPayloadFactory};
pub use reliability::{Reliability, ReliabilityCodec, ReliabilityHandle};
pub use resumption::{
    ResumptionClient, ResumptionCodec, ResumptionHandle, ResumptionMap, ResumptionServer,
};
pub use routing::{RoutingClient, RoutingCodec, RoutingError, RoutingHandle, RoutingServer};

/// Implements FrameSize for any Protocol with a Codec implementing FrameSize.
impl<T> FrameSize for T
where
    T: Protocol,
    <Self as Protocol>::Codec: FrameSize,
{
    fn mtu() -> usize {
        <Self as Protocol>::Codec::mtu()
    }

    fn mss(target_mtu: usize) -> usize {
        <Self as Protocol>::Codec::mss(target_mtu)
    }
}

#[cfg(test)]
pub mod tests {
    use tokio_test::assert_ok;

    use crate::FrameSize;
    use crate::net::{NetworkAddress, NetworkTarget};
    use crate::proto::framing::{Framing, FramingCodec};
    use crate::proto::payload::{Payload, TcpPayload, TcpPayloadFactory};
    use crate::proto::reliability::{Reliability, ReliabilityCodec};
    use crate::proto::resumption::{ResumptionClient, ResumptionCodec, ResumptionServer};
    use crate::proto::routing::{RoutingClient, RoutingServer};
    use crate::test::{TestConnector, TestIoProtocol, TestNetwork, TestPayload};
    use crate::util::EndMethod;

    const SESSION_ID: u64 = 5;

    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}

    #[test]
    fn protocol_stacks_are_send() {
        assert_send::<TcpPayload>();

        assert_send::<Framing<TcpPayload>>();
        assert_send::<Reliability<TcpPayload>>();
        assert_send::<RoutingClient<TcpPayload>>();
        assert_send::<RoutingServer<TcpPayload, TcpPayloadFactory>>();
        assert_send::<ResumptionClient<TcpPayload>>();
        assert_send::<ResumptionServer<TcpPayload>>();

        // Supporting session resumption but without a server-side connecting
        // proxy. This would be the mode used in a Tor pluggable transport.
        assert_send::<Framing<ResumptionClient<Reliability<TcpPayload>>>>();
        assert_send::<Framing<ResumptionServer<Reliability<TcpPayload>>>>();

        // A server-side connecting proxy without session resumption.
        assert_send::<Framing<RoutingClient<TcpPayload>>>();
        assert_send::<Framing<RoutingServer<TcpPayload, TcpPayloadFactory>>>();

        // A server-side connecting proxy with session resumption.
        assert_send::<Framing<ResumptionClient<Reliability<RoutingClient<TcpPayload>>>>>();
        assert_send::<
            Framing<ResumptionServer<Reliability<RoutingServer<TcpPayload, TcpPayloadFactory>>>>,
        >();
    }

    #[test]
    fn protocol_stacks_are_sync() {
        assert_sync::<TcpPayload>();

        assert_sync::<Framing<TcpPayload>>();
        assert_sync::<Reliability<TcpPayload>>();
        assert_sync::<RoutingClient<TcpPayload>>();
        assert_sync::<RoutingServer<TcpPayload, TcpPayloadFactory>>();
        assert_sync::<ResumptionClient<TcpPayload>>();
        assert_sync::<ResumptionServer<TcpPayload>>();

        // Supporting session resumption but without a server-side connecting
        // proxy. This would be the mode used in a Tor pluggable transport.
        assert_sync::<Framing<ResumptionClient<Reliability<TcpPayload>>>>();
        assert_sync::<Framing<ResumptionServer<Reliability<TcpPayload>>>>();

        // A server-side connecting proxy without session resumption.
        assert_sync::<Framing<RoutingClient<TcpPayload>>>();
        assert_sync::<Framing<RoutingServer<TcpPayload, TcpPayloadFactory>>>();

        // A server-side connecting proxy with session resumption.
        assert_sync::<Framing<ResumptionClient<Reliability<RoutingClient<TcpPayload>>>>>();
        assert_sync::<
            Framing<ResumptionServer<Reliability<RoutingServer<TcpPayload, TcpPayloadFactory>>>>,
        >();
    }

    #[tokio::test]
    async fn protocol_stack_framing_payload() {
        for (c_io, s_io, len) in TestPayload::iter() {
            let (c_r, c_w) = tokio::io::split(c_io);
            let (s_r, s_w) = tokio::io::split(s_io);

            let app_msg_mss = FramingCodec::mss(FramingCodec::mtu());
            let client = Framing::new(Payload::new(SESSION_ID, c_r, c_w, app_msg_mss));
            let server = Framing::new(Payload::new(SESSION_ID, s_r, s_w, app_msg_mss));

            let network = TestNetwork::new(client, server);
            let (c_to_s_result, s_to_c_result) = network.run().await;

            assert_ok!(c_to_s_result);
            assert_ok!(s_to_c_result);
            assert!(c_to_s_result.unwrap() >= len);
            assert!(s_to_c_result.unwrap() >= len);
        }
    }

    #[tokio::test]
    async fn protocol_stack_reliability_payload() {
        for (c_io, s_io, len) in TestPayload::iter() {
            let (c_r, c_w) = tokio::io::split(c_io);
            let (s_r, s_w) = tokio::io::split(s_io);

            let app_msg_mss = ReliabilityCodec::mss(ReliabilityCodec::mtu());
            let client = Reliability::new(Payload::new(SESSION_ID, c_r, c_w, app_msg_mss));
            let server = Reliability::new(Payload::new(SESSION_ID, s_r, s_w, app_msg_mss));

            let network = TestNetwork::new(client, server);
            let (c_to_s_result, s_to_c_result) = network.run().await;

            assert_ok!(c_to_s_result);
            assert_ok!(s_to_c_result);
            assert!(c_to_s_result.unwrap() >= len);
            assert!(s_to_c_result.unwrap() >= len);
        }
    }

    #[tokio::test]
    async fn protocol_stack_framing_reliability_payload() {
        for (c_io, s_io, len) in TestPayload::iter() {
            let (c_r, c_w) = tokio::io::split(c_io);
            let (s_r, s_w) = tokio::io::split(s_io);

            let app_msg_mss = ReliabilityCodec::mss(FramingCodec::mss(FramingCodec::mtu()));

            let c_app = Payload::new(SESSION_ID, c_r, c_w, app_msg_mss);
            let client = Framing::new(Reliability::new(c_app));

            let s_app = Payload::new(SESSION_ID, s_r, s_w, app_msg_mss);
            let server = Framing::new(Reliability::new(s_app));

            let network = TestNetwork::new(client, server);
            let (c_to_s_result, s_to_c_result) = network.run().await;

            assert_ok!(c_to_s_result);
            assert_ok!(s_to_c_result);
            assert!(c_to_s_result.unwrap() >= len);
            assert!(s_to_c_result.unwrap() >= len);
        }
    }

    #[tokio::test]
    async fn protocol_stack_framing_resumption_reliability_payload() {
        for (c_io, s_io, len) in TestPayload::iter() {
            let (c_r, c_w) = tokio::io::split(c_io);
            let (s_r, s_w) = tokio::io::split(s_io);

            let app_msg_mss =
                ReliabilityCodec::mss(ResumptionCodec::mss(FramingCodec::mss(FramingCodec::mtu())));

            let c_app = Payload::new(SESSION_ID, c_r, c_w, app_msg_mss);
            let client = Framing::new(ResumptionClient::new(Reliability::new(c_app)));

            let s_app = Payload::new(SESSION_ID, s_r, s_w, app_msg_mss);
            let server = Framing::new(ResumptionServer::new(Reliability::new(s_app)));

            let network = TestNetwork::new(client, server);
            let (c_to_s_result, s_to_c_result) = network.run().await;

            assert_ok!(c_to_s_result);
            assert_ok!(s_to_c_result);
            assert!(c_to_s_result.unwrap() >= len);
            assert!(s_to_c_result.unwrap() >= len);
        }
    }

    #[tokio::test]
    async fn protocol_stack_framing_resumption_reliability_routing_payload() {
        for (c_io, s_io, len) in TestPayload::iter() {
            let mut connector = TestConnector::new();
            connector.push(TestIoProtocol::from_mock(s_io)).await;

            let client = RoutingClient::new();
            let mut handle = client.handle().clone();
            let client = Framing::new(ResumptionClient::new(Reliability::new(client)));

            let server = RoutingServer::new(connector).await;
            let server = Framing::new(ResumptionServer::new(Reliability::new(server)));

            let network_handle = tokio::spawn(async move {
                let network = TestNetwork::new(client, server);
                network.run().await
            });

            let name = String::from("mock_connection");
            let target = NetworkTarget::new(NetworkAddress::from(name), 0);
            let session_id = assert_ok!(handle.connect_session(target, None).await);

            let client_data = TestIoProtocol::from_mock(c_io).with_id(session_id);
            assert_ok!(handle.add_session(session_id, client_data).await);
            assert_ok!(handle.set_end_method(EndMethod::Empty).await);

            let (c_to_s_result, s_to_c_result) = assert_ok!(network_handle.await);
            assert_ok!(c_to_s_result);
            assert_ok!(s_to_c_result);
            assert!(c_to_s_result.unwrap() >= len);
            assert!(s_to_c_result.unwrap() >= len);
        }
    }
}
