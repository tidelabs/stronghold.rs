// Copyright 2020-2021 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

// Copyright 2020 Parity Technologies (UK) Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

#[doc(hidden)]
mod addresses;
pub mod firewall;
#[doc(hidden)]
mod handler;
#[doc(hidden)]
mod request_manager;
pub use addresses::{assemble_relayed_addr, AddressInfo, PeerAddress};
use firewall::{FirewallRequest, FirewallRules, FwRequest, Rule};
use futures::{
    channel::{
        mpsc::{self, SendError},
        oneshot,
    },
    future::{poll_fn, BoxFuture},
    select_biased,
    stream::FuturesUnordered,
    task::{Context, Poll},
    FutureExt, StreamExt, TryFutureExt,
};
pub use handler::MessageProtocol;
use handler::{Handler, HandlerInEvent, HandlerOutEvent};
use libp2p::{
    core::{
        connection::{ConnectionId, ListenerId},
        either::EitherOutput,
        ConnectedPoint, Multiaddr, PeerId,
    },
    mdns::Mdns,
    relay::v1::Relay,
    swarm::{
        behaviour::toggle::Toggle,
        dial_opts::{DialOpts, PeerCondition},
        ConnectionHandler, IntoConnectionHandler, IntoConnectionHandlerSelect,
        NetworkBehaviour as Libp2pNetworkBehaviour, NetworkBehaviourAction, NotifyHandler, PollParameters,
    },
};
use request_manager::{ApprovalStatus, BehaviourAction, RequestManager};
use serde::{de::DeserializeOwned, Serialize};
use smallvec::{smallvec, SmallVec};
use std::{
    collections::HashMap,
    fmt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use wasm_timer::Delay;

type ProtoHandler<Rq, Rs> = IntoConnectionHandlerSelect<
    Handler<Rq, Rs>,
    IntoConnectionHandlerSelect<
        <Toggle<Mdns> as Libp2pNetworkBehaviour>::ConnectionHandler,
        <Toggle<Relay> as Libp2pNetworkBehaviour>::ConnectionHandler,
    >,
>;

// Future for a pending response to a sent `FirewallRequest::PeerSpecificRule`.
type PendingPeerRuleRequest<TRq> = BoxFuture<'static, (PeerId, Option<Rule<TRq>>)>;
// Future for a pending responses to a sent `FirewallRequest::RequestApproval`.
type PendingApprovalRequest = BoxFuture<'static, (RequestId, bool)>;

const EMPTY_QUEUE_SHRINK_THRESHOLD: usize = 100;

/// Protocol for customization for the `Swarm`[libp2p::Swarm].
///
/// The protocol is based on the `RequestResponse`[<https://docs.rs/libp2p-request-response>] protocol from libp2p
/// and optionally integrates the libp2p `Relay`[libp2p::relay::v1::Relay] and `Mdns`[libp2p::mdns::Mdns] protocols.
///
/// This allows sending request messages to remote peers, handling of inbound requests and failures, and additionally
/// the configuration of a firewall to set permissions individually for different peers and request types.
pub struct NetworkBehaviour<Rq, Rs, TRq = Rq>
where
    Rq: Request,
    Rs: Request,
    TRq: FwRequest<Rq>,
{
    // Integrate Mdns protocol.
    mdns: Toggle<Mdns>,

    // Integrate Relay protocol.
    relay: Toggle<Relay>,

    // Timeout and protocol configurations.
    config: ConfigConfig,

    // ID assigned to the next request.
    next_request_id: Arc<AtomicU64>,

    // Manager for pending requests, their state and necessary actions.
    request_manager: RequestManager<Rq, Rs>,
    // Address information and relay settings for known peers.
    addresses: AddressInfo,
    // Configuration of the firewall.
    // Each inbound request is checked, and only forwarded if the firewall configuration approves the request
    // for this peer.
    firewall: FirewallRules<TRq>,

    // Channel for firewall requests.
    // The channel is used if there is no rule set for a peer, or if the configuration demands individual approval for
    // each request.
    permission_req_channel: mpsc::Sender<FirewallRequest<TRq>>,
    // Futures for pending responses to sent `FirewallRequest::PeerSpecificRule`s.
    pending_rule_rqs: FuturesUnordered<PendingPeerRuleRequest<TRq>>,
    // Futures for pending responses to sent `FirewallRequest::RequestApproval`s.
    pending_approval_rqs: FuturesUnordered<PendingApprovalRequest>,

    // Handles to pending firewall rule request. If the handle is dropped, the future is aborted.
    rule_rq_handles: HashMap<PeerId, oneshot::Sender<()>>,

    // Handles to pending approval requests. If the handle is dropped, the future is aborted.
    approval_rq_handles: HashMap<RequestId, oneshot::Sender<()>>,
}

impl<Rq, Rs, TRq> NetworkBehaviour<Rq, Rs, TRq>
where
    Rq: Request,
    Rs: Request,
    TRq: FwRequest<Rq>,
{
    /// Create a new NetworkBehaviour for the libp2p swarm.
    pub fn new(
        config: ConfigConfig,
        mdns: Option<Mdns>,
        relay: Option<Relay>,
        permission_req_channel: mpsc::Sender<FirewallRequest<TRq>>,
        firewall: FirewallRules<TRq>,
        address_info: Option<AddressInfo>,
    ) -> Self {
        NetworkBehaviour {
            mdns: mdns.into(),
            relay: relay.into(),
            config,
            next_request_id: Arc::new(AtomicU64::new(1)),
            request_manager: RequestManager::new(),
            addresses: address_info.unwrap_or_default(),
            firewall,
            permission_req_channel,
            pending_rule_rqs: FuturesUnordered::default(),
            rule_rq_handles: HashMap::new(),
            pending_approval_rqs: FuturesUnordered::default(),
            approval_rq_handles: HashMap::new(),
        }
    }

    /// Send a new request to a remote peer.
    pub fn send_request(&mut self, peer: PeerId, request: Rq) -> RequestId {
        let request_id = RequestId::next(&self.next_request_id);
        self.request_manager.on_new_out_request(peer, request_id, request);
        request_id
    }

    /// Get the current default  for the firewall.
    pub fn get_firewall_config(&self) -> &FirewallRules<TRq> {
        &self.firewall
    }

    /// Set the default configuration for the firewall.
    pub fn set_firewall_default(&mut self, default: Option<Rule<TRq>>) {
        self.firewall.set_default(default);
        self.request_manager.connected_peers().into_iter().for_each(|peer| {
            if self.firewall.get_rule(&peer).is_none() {
                self.handle_updated_peer_rule(peer);
            }
        })
    }

    /// Remove a default firewall rule.
    /// If there is no default rule and no peer-specific rule, a `FirewallRequest::PeerSpecificRule`
    /// request will be sent through the firewall channel
    pub fn remove_firewall_default(&mut self) {
        if self.firewall.get_default_rule().is_none() {
            return;
        }
        self.request_manager.connected_peers().into_iter().for_each(|peer| {
            if self.firewall.get_rule(&peer).is_none() {
                self.handle_updated_peer_rule(peer);
            }
        })
    }

    /// Set a peer specific rule to overwrite the default behaviour for that peer.
    pub fn set_peer_rule(&mut self, peer: PeerId, rule: Rule<TRq>) {
        self.firewall.set_rule(peer, rule);
        self.handle_updated_peer_rule(peer);
    }

    /// Remove a peer specific rule, which will result in using the firewall default rule.
    pub fn remove_peer_rule(&mut self, peer: PeerId) {
        self.firewall.remove_rule(&peer);
        self.handle_updated_peer_rule(peer);
    }

    /// Add an address for the remote peer.
    pub fn add_address(&mut self, peer: PeerId, address: Multiaddr) {
        self.addresses.add_addrs(peer, address);
    }

    /// Remove an address from the known addresses of a remote peer.
    pub fn remove_address(&mut self, peer: &PeerId, address: &Multiaddr) {
        self.addresses.remove_address(peer, address);
    }

    /// Export collected info about known relays and peer addresses.
    pub fn export_address_info(&self) -> AddressInfo {
        self.addresses.clone()
    }

    /// Get currently established connections.
    pub fn established_connections(&self) -> Vec<(PeerId, Vec<ConnectedPoint>)> {
        self.request_manager.established_connections()
    }

    /// Whether the relay protocol is enabled.
    pub fn is_relay_enabled(&self) -> bool {
        self.relay.is_enabled()
    }

    /// Add a relay to the list of relays that may be tried to use if a remote peer can not be reached directly.
    pub fn add_dialing_relay(
        &mut self,
        peer: PeerId,
        address: Option<Multiaddr>,
    ) -> Result<Option<Multiaddr>, RelayNotSupported> {
        if !self.is_relay_enabled() {
            return Err(RelayNotSupported);
        }
        Ok(self.addresses.add_relay(peer, address))
    }

    /// Remove a relay from the list of dialing relays.
    /// Returns `false` if the peer was not among the known relays.
    ///
    /// **Note**: Known relayed addresses for remote peers using this relay will not be influenced by this.
    pub fn remove_dialing_relay(&mut self, peer: &PeerId) -> bool {
        self.addresses.remove_relay(peer)
    }

    /// Configure whether it should be attempted to reach the remote via known relays, if it can not be reached via
    /// known addresses.
    pub fn set_relay_fallback(&mut self, peer: PeerId, use_relay_fallback: bool) -> Result<(), RelayNotSupported> {
        if !self.is_relay_enabled() {
            return Err(RelayNotSupported);
        }
        self.addresses.set_relay_fallback(peer, use_relay_fallback);
        Ok(())
    }

    /// Dial the target via the specified relay.
    /// The `is_exclusive` parameter specifies whether other known relays should be used if using the set relay is not
    /// successful.
    ///
    /// Returns the relayed address of the local peer (`<relay-addr>/<relay-id>/p2p-circuit/<local-id>),
    /// if an address for the relay is known.
    pub fn use_specific_relay(
        &mut self,
        target: PeerId,
        relay: PeerId,
        is_exclusive: bool,
    ) -> Result<Option<Multiaddr>, RelayNotSupported> {
        if !self.is_relay_enabled() {
            return Err(RelayNotSupported);
        }
        Ok(self.addresses.use_relay(target, relay, is_exclusive))
    }

    // Check the approval status of the request and add queries to the firewall if necessary.
    fn check_approval_status(&mut self, peer: PeerId, request_id: RequestId, request: &Rq) -> ApprovalStatus {
        // Check the firewall rule for the target peer.
        match self.firewall.get_effective_rule(&peer) {
            None => {
                // Query for a new peer specific rule.
                self.query_peer_rule(peer);
                ApprovalStatus::MissingRule
            }
            Some(Rule::Ask) => {
                // Query for individual approval for the requests.
                self.query_request_approval(peer, request_id, TRq::from_request(request));
                ApprovalStatus::MissingApproval
            }
            Some(Rule::AllowAll) => ApprovalStatus::Approved,
            Some(Rule::RejectAll) => ApprovalStatus::Rejected,
            Some(Rule::Restricted { restriction, .. }) => {
                if restriction(&TRq::from_request(request)) {
                    ApprovalStatus::Approved
                } else {
                    ApprovalStatus::Rejected
                }
            }
        }
    }

    fn new_request_response_handler(&mut self, peer: Option<PeerId>) -> Handler<Rq, Rs> {
        let inbound_support = match peer {
            Some(peer) => !matches!(self.firewall.get_effective_rule(&peer), Some(Rule::RejectAll)),
            None => true,
        };
        // Use full protocol support on init.
        // Once the connection is established, this will be updated with the effective rule for the remote peer.
        Handler::new(
            self.config.supported_protocols.clone(),
            inbound_support,
            self.config.connection_timeout,
            self.config.request_timeout,
            self.next_request_id.clone(),
        )
    }

    fn new_handler_for_peer(&mut self, peer: Option<PeerId>) -> <Self as Libp2pNetworkBehaviour>::ConnectionHandler {
        let handler = self.new_request_response_handler(peer);
        let mdns_handler = self.mdns.new_handler();
        let relay_handler = self.relay.new_handler();
        IntoConnectionHandler::select(handler, IntoConnectionHandler::select(mdns_handler, relay_handler))
    }

    // Handle new event emitted by the `Handler`.
    fn handle_handler_event(&mut self, peer: PeerId, connection: ConnectionId, event: HandlerOutEvent<Rq, Rs>) {
        match event {
            HandlerOutEvent::ReceivedRequest {
                request_id,
                request,
                response_tx,
            } => {
                let approval_status = self.check_approval_status(peer, request_id, &request);
                self.request_manager.on_new_in_request(
                    peer,
                    request_id,
                    request,
                    response_tx,
                    connection,
                    approval_status,
                );
            }
            HandlerOutEvent::ReceivedResponse { request_id, response } => {
                self.request_manager.on_res_for_outbound(peer, request_id, Ok(response));
            }
            HandlerOutEvent::OutboundTimeout(request_id) => {
                // Abort firewall request for approval.
                let _ = self.approval_rq_handles.remove(&request_id);
                self.request_manager
                    .on_res_for_outbound(peer, request_id, Err(OutboundFailure::Timeout));
            }
            HandlerOutEvent::OutboundUnsupportedProtocols(request_id) => {
                // Abort firewall request for approval.
                let _ = self.approval_rq_handles.remove(&request_id);
                self.request_manager
                    .on_res_for_outbound(peer, request_id, Err(OutboundFailure::UnsupportedProtocols));
            }
            HandlerOutEvent::InboundTimeout(request_id) => {
                // Abort firewall request for approval.
                let _ = self.approval_rq_handles.remove(&request_id);
                let err = InboundFailure::Timeout;
                self.request_manager.on_res_for_inbound(peer, request_id, Err(err));
            }
            HandlerOutEvent::InboundUnsupportedProtocols(request_id)
            | HandlerOutEvent::SendResponseOmission(request_id)
            | HandlerOutEvent::SentResponse(request_id) => {
                // Abort firewall request for approval.
                let _ = self.approval_rq_handles.remove(&request_id);
                self.request_manager.on_res_for_inbound(peer, request_id, Ok(()));
            }
        }
    }

    // Query for a new peer-specific firewall rule, if there is no pending request for this yet.
    fn query_peer_rule(&mut self, peer: PeerId) {
        // Only query for rule if there is no pending request.
        if self.request_manager.is_rule_request_pending(&peer) {
            return;
        }
        let (rule_tx, rule_rx) = oneshot::channel();
        let (abort_handle_tx, abort_handle_rx) = oneshot::channel();
        let timeout = Delay::new(self.config.firewall_timeout);

        let firewall_req = FirewallRequest::<TRq>::PeerSpecificRule { peer, rule_tx };
        // Send request through the firewall channel, add to pending rule requests.
        let send_firewall = Self::send_firewall(self.permission_req_channel.clone(), firewall_req).map_err(|_| ());

        let future = send_firewall
            .and_then(move |()| async {
                select_biased! {
                    res = rule_rx.fuse() => res.map_err(|_| ()),
                    _ = timeout.fuse() => Err(()),
                    _ = abort_handle_rx.fuse() => Err(())

                }
            })
            .map_ok_or_else(move |()| (peer, None), move |rule| (peer, Some(rule)))
            .boxed();
        self.pending_rule_rqs.push(future);
        self.rule_rq_handles.insert(peer, abort_handle_tx);
        self.request_manager.add_pending_rule_request(peer);
    }

    // Query for individual approval of a requests.
    // This is necessary if the firewall is configured with `Rule::Ask`.
    //
    // A clone of the response-sender is handed. It is polled while a response from the firewall
    // is awaited
    fn query_request_approval(&mut self, peer: PeerId, request_id: RequestId, rq: TRq) {
        let (approval_tx, approval_rx) = oneshot::channel();
        let (abort_handle_tx, abort_handle_rx) = oneshot::channel();
        let timeout = Delay::new(self.config.firewall_timeout);

        let firewall_req = FirewallRequest::RequestApproval {
            peer,
            request: rq,
            approval_tx,
        };
        let send_firewall = Self::send_firewall(self.permission_req_channel.clone(), firewall_req).map_err(|_| ());
        let future = send_firewall
            .and_then(move |()| async {
                select_biased! {
                    res = approval_rx.fuse() => res.map_err(|_| ()),
                    _ = timeout.fuse() => Err(()),
                    _ = abort_handle_rx.fuse() => Err(())

                }
            })
            .map_ok_or_else(move |()| (request_id, false), move |b| (request_id, b))
            .boxed();

        self.pending_approval_rqs.push(future);
        self.approval_rq_handles.insert(request_id, abort_handle_tx);
    }

    // Send a request through the firewall channel.
    async fn send_firewall(
        mut channel: mpsc::Sender<FirewallRequest<TRq>>,
        request: FirewallRequest<TRq>,
    ) -> Result<(), SendError> {
        poll_fn(|cx: &mut Context<'_>| channel.poll_ready(cx)).await?;
        channel.start_send(request)
    }

    // Handle a changed firewall rule for a peer.
    fn handle_updated_peer_rule(&mut self, peer: PeerId) {
        // Set inbound protocol support for the active handlers according to the new rule.
        let rule = self.firewall.get_effective_rule(&peer);
        let inbound_support = !matches!(rule, Some(Rule::RejectAll));
        self.request_manager.set_inbound_support(peer, None, inbound_support);
        // Query for individual request approval due to `Rule::Ask`.
        if let Some(ask_reqs) = self.request_manager.on_peer_rule(peer, rule.cloned()) {
            ask_reqs.into_iter().for_each(|(id, rq)| {
                self.query_request_approval(peer, id, rq);
            })
        }
    }
}

impl<Rq, Rs, TRq> Libp2pNetworkBehaviour for NetworkBehaviour<Rq, Rs, TRq>
where
    Rq: Request,
    Rs: Request,
    TRq: FwRequest<Rq>,
{
    type ConnectionHandler = ProtoHandler<Rq, Rs>;
    type OutEvent = BehaviourEvent<Rq, Rs>;

    fn new_handler(&mut self) -> Self::ConnectionHandler {
        self.new_handler_for_peer(None)
    }

    fn inject_event(
        &mut self,
        peer: PeerId,
        connection: ConnectionId,
        event: <<Self::ConnectionHandler as IntoConnectionHandler>::Handler as ConnectionHandler>::OutEvent,
    ) {
        match event {
            EitherOutput::First(ev) => self.handle_handler_event(peer, connection, ev),
            EitherOutput::Second(EitherOutput::First(ev)) => self.mdns.inject_event(peer, connection, ev),
            EitherOutput::Second(EitherOutput::Second(ev)) => self.relay.inject_event(peer, connection, ev),
        };
    }

    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        _params: &mut impl PollParameters,
    ) -> Poll<NetworkBehaviourAction<Self::OutEvent, Self::ConnectionHandler>> {
        // Drive mdns.
        let _ = self.mdns.poll(cx, _params);

        // Update firewall rule if a peer specific rule was returned after a `FirewallRequest::PeerSpecificRule` query.
        while let Poll::Ready(Some((peer, rule))) = self.pending_rule_rqs.poll_next_unpin(cx) {
            if let Some(rule) = rule {
                self.firewall.set_rule(peer, rule);
            }
            self.handle_updated_peer_rule(peer);
        }

        // Handle individual approvals for requests that were returned after a `FirewallRequest::RequestApproval`
        // query.
        while let Poll::Ready(Some((request_id, is_allowed))) = self.pending_approval_rqs.poll_next_unpin(cx) {
            self.request_manager.on_request_approval(request_id, is_allowed);
        }

        // Handle events from the relay protocol.
        if let Poll::Ready(action) = self.relay.poll(cx, _params) {
            match action {
                NetworkBehaviourAction::Dial {
                    opts,
                    handler: relay_handler,
                } => {
                    let rq_rs_handler = self.new_request_response_handler(opts.get_peer_id());
                    let mdns_handler = self.mdns.new_handler();
                    let handler = IntoConnectionHandler::select(
                        rq_rs_handler,
                        IntoConnectionHandler::select(mdns_handler, relay_handler),
                    );
                    return Poll::Ready(NetworkBehaviourAction::Dial { opts, handler });
                }
                NetworkBehaviourAction::NotifyHandler {
                    peer_id,
                    handler,
                    event,
                } => {
                    let event = EitherOutput::Second(EitherOutput::Second(event));
                    return Poll::Ready(NetworkBehaviourAction::NotifyHandler {
                        peer_id,
                        handler,
                        event,
                    });
                }
                _ => {}
            }
        }
        // Emit events for pending requests and required dial attempts.
        if let Some(event) = self.request_manager.take_next_action() {
            let action = match event {
                BehaviourAction::InboundOk {
                    request_id,
                    peer,
                    request,
                    response_tx,
                } => NetworkBehaviourAction::GenerateEvent(BehaviourEvent::ReceivedRequest {
                    peer,
                    request_id,
                    request,
                    response_tx,
                }),
                BehaviourAction::InboundFailure {
                    request_id,
                    peer,
                    failure,
                } => NetworkBehaviourAction::GenerateEvent(BehaviourEvent::InboundFailure {
                    peer,
                    request_id,
                    failure,
                }),
                BehaviourAction::OutboundOk {
                    request_id,
                    peer,
                    request,
                    connection,
                } => {
                    let event = HandlerInEvent::SendRequest { request_id, request };
                    NetworkBehaviourAction::NotifyHandler {
                        peer_id: peer,
                        handler: NotifyHandler::One(connection),
                        event: EitherOutput::First(event),
                    }
                }
                BehaviourAction::OutboundFailure {
                    request_id,
                    peer,
                    failure,
                } => NetworkBehaviourAction::GenerateEvent(BehaviourEvent::OutboundFailure {
                    peer,
                    request_id,
                    failure,
                }),
                BehaviourAction::OutboundReceivedRes {
                    request_id,
                    peer,
                    response,
                } => NetworkBehaviourAction::GenerateEvent(BehaviourEvent::ReceivedResponse {
                    peer,
                    request_id,
                    response,
                }),
                BehaviourAction::RequireDialAttempt(peer) => NetworkBehaviourAction::Dial {
                    handler: self.new_handler_for_peer(Some(peer)),
                    opts: DialOpts::peer_id(peer).condition(PeerCondition::Disconnected).build(),
                },
                BehaviourAction::SetInboundSupport {
                    peer,
                    connection,
                    support,
                } => {
                    let event = HandlerInEvent::SetInboundSupport(support);
                    NetworkBehaviourAction::NotifyHandler {
                        peer_id: peer,
                        handler: NotifyHandler::One(connection),
                        event: EitherOutput::First(event),
                    }
                }
            };
            return Poll::Ready(action);
        }
        Poll::Pending
    }

    fn addresses_of_peer(&mut self, peer: &PeerId) -> Vec<Multiaddr> {
        let mut addresses = self.addresses.get_addrs(peer);
        if let Some(relay) = self.relay.as_mut() {
            addresses.extend(relay.addresses_of_peer(peer));
        }
        if let Some(mdns) = self.mdns.as_mut() {
            addresses.extend(mdns.addresses_of_peer(peer));
        }
        addresses
    }

    fn inject_connection_established(
        &mut self,
        peer: &PeerId,
        connection: &ConnectionId,
        endpoint: &ConnectedPoint,
        failed_addresses: Option<&Vec<Multiaddr>>,
        _other_established: usize,
    ) {
        // If the remote connected to us and there is no rule for inbound requests yet, query firewall.
        if endpoint.is_listener() && self.firewall.get_effective_rule(peer).is_none() {
            self.query_peer_rule(*peer);
        }
        // Set the protocol support for the remote peer.
        let support_inbound = !matches!(self.firewall.get_effective_rule(peer), Some(Rule::RejectAll));
        self.request_manager
            .set_inbound_support(*peer, Some(*connection), support_inbound);

        if let Some(addrs) = failed_addresses {
            for addr in addrs {
                self.addresses.deprioritize_addr(*peer, addr.clone());
            }
        }

        self.request_manager
            .on_connection_established(*peer, *connection, endpoint.clone());
        self.addresses
            .prioritize_addr(*peer, endpoint.get_remote_address().clone());

        if let Some(relay) = self.relay.as_mut() {
            relay.inject_connection_established(peer, connection, endpoint, failed_addresses, _other_established);
        }

        if let Some(mdns) = self.mdns.as_mut() {
            mdns.inject_connection_established(peer, connection, endpoint, failed_addresses, _other_established);
        }
    }

    fn inject_connection_closed(
        &mut self,
        peer: &PeerId,
        connection: &ConnectionId,
        _endpoint: &ConnectedPoint,
        _handler: <Self::ConnectionHandler as IntoConnectionHandler>::Handler,
        remaining_established: usize,
    ) {
        self.request_manager
            .on_connection_closed(*peer, connection, remaining_established);
        // Abort pending requests for firewall rule, if the peer completely disconnected.
        if remaining_established == 0 {
            let _ = self.rule_rq_handles.remove(peer);
        }
        let (_, select) = _handler.into_inner();
        let (mdns_handler, relay_handler) = select.into_inner();
        self.mdns
            .inject_connection_closed(peer, connection, _endpoint, mdns_handler, remaining_established);
        self.relay
            .inject_connection_closed(peer, connection, _endpoint, relay_handler, remaining_established);
    }

    fn inject_address_change(
        &mut self,
        peer: &PeerId,
        connection: &ConnectionId,
        _old: &ConnectedPoint,
        new: &ConnectedPoint,
    ) {
        self.request_manager.on_address_change(*peer, *connection, new.clone());
        if let Some(relay) = self.relay.as_mut() {
            relay.inject_address_change(peer, connection, _old, new);
        }

        if let Some(mdns) = self.mdns.as_mut() {
            mdns.inject_address_change(peer, connection, _old, new);
        }
    }

    fn inject_dial_failure(
        &mut self,
        peer_id: Option<PeerId>,
        _handler: Self::ConnectionHandler,
        _error: &libp2p::swarm::DialError,
    ) {
        if let Some(peer) = peer_id {
            self.request_manager.on_dial_failure(peer);
        }
        let (_, select) = _handler.into_inner();
        let (mdns_handler, relay_handler) = select.into_inner();
        self.mdns.inject_dial_failure(peer_id, mdns_handler, _error);
        self.relay.inject_dial_failure(peer_id, relay_handler, _error);
    }

    fn inject_listen_failure(
        &mut self,
        _local_addr: &Multiaddr,
        _send_back_addr: &Multiaddr,
        _handler: Self::ConnectionHandler,
    ) {
        let (_, select) = _handler.into_inner();
        let (mdns_handler, relay_handler) = select.into_inner();
        self.mdns
            .inject_listen_failure(_local_addr, _send_back_addr, mdns_handler);
        self.relay
            .inject_listen_failure(_local_addr, _send_back_addr, relay_handler);
    }

    fn inject_new_listener(&mut self, id: ListenerId) {
        self.mdns.inject_new_listener(id);
        self.relay.inject_new_listener(id);
    }

    fn inject_new_listen_addr(&mut self, _id: ListenerId, _addr: &Multiaddr) {
        if let Some(mdns) = self.mdns.as_mut() {
            mdns.inject_new_listen_addr(_id, _addr);
        }
        if let Some(relay) = self.relay.as_mut() {
            relay.inject_new_listen_addr(_id, _addr);
        }
    }

    fn inject_expired_listen_addr(&mut self, id: ListenerId, addr: &Multiaddr) {
        if let Some(mdns) = self.mdns.as_mut() {
            mdns.inject_expired_listen_addr(id, addr);
        }
        if let Some(relay) = self.relay.as_mut() {
            relay.inject_expired_listen_addr(id, addr);
        }
    }

    fn inject_listener_error(&mut self, id: ListenerId, err: &(dyn std::error::Error + 'static)) {
        if let Some(mdns) = self.mdns.as_mut() {
            mdns.inject_listener_error(id, err);
        }
        if let Some(relay) = self.relay.as_mut() {
            relay.inject_listener_error(id, err);
        }
    }

    fn inject_listener_closed(&mut self, id: ListenerId, reason: Result<(), &std::io::Error>) {
        if let Some(mdns) = self.mdns.as_mut() {
            mdns.inject_listener_closed(id, reason);
        }
        if let Some(relay) = self.relay.as_mut() {
            relay.inject_listener_closed(id, reason);
        }
    }

    fn inject_new_external_addr(&mut self, addr: &Multiaddr) {
        if let Some(mdns) = self.mdns.as_mut() {
            mdns.inject_new_external_addr(addr);
        }
        if let Some(relay) = self.relay.as_mut() {
            relay.inject_new_external_addr(addr);
        }
    }

    fn inject_expired_external_addr(&mut self, addr: &Multiaddr) {
        if let Some(mdns) = self.mdns.as_mut() {
            mdns.inject_expired_external_addr(addr);
        }
        if let Some(relay) = self.relay.as_mut() {
            relay.inject_expired_external_addr(addr);
        }
    }
}

/// Trait for the generic request and response messages.
pub trait Request: Serialize + DeserializeOwned + Send + Sync + fmt::Debug + 'static {}
impl<TRq: Serialize + DeserializeOwned + Send + Sync + fmt::Debug + 'static> Request for TRq {}

/// Unique Id for each request.
/// **Note**: This ID is only local and does not match the request's ID at the remote peer.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(u64);

impl RequestId {
    // Adds to the given value, returning the previous value as RequestId.
    pub(crate) fn next(value: &Arc<AtomicU64>) -> Self {
        RequestId(value.fetch_add(1, Ordering::Relaxed))
    }

    pub(crate) fn value(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Configuration of the `NetworkBehaviour`.
pub struct ConfigConfig {
    /// Supported versions of the `MessageProtocol`.
    pub supported_protocols: SmallVec<[MessageProtocol; 2]>,
    /// Timeout for inbound and outbound requests.
    pub request_timeout: Duration,
    /// Keep-alive timeout of idle connections.
    pub connection_timeout: Duration,
    /// Timeout for `FirewallRequest`s send through the firewall-channel.
    ///
    /// See `StrongholdP2p` docs for more info.
    pub firewall_timeout: Duration,
}

impl Default for ConfigConfig {
    fn default() -> Self {
        Self {
            supported_protocols: smallvec![MessageProtocol::new_version(1, 0, 0)],
            connection_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(10),
            firewall_timeout: Duration::from_secs(10),
        }
    }
}

/// Requests and failure events emitted by the `NetworkBehaviour`.
#[derive(Debug)]
pub enum BehaviourEvent<Rq, Rs> {
    /// An inbound request was received from a remote peer.
    /// The request was checked and approved by the firewall.
    ReceivedRequest {
        request_id: RequestId,
        peer: PeerId,
        /// Request from the remote peer.
        request: Rq,
        /// Channel for returning the response
        response_tx: oneshot::Sender<Rs>,
    },
    /// A failure occurred in the context of receiving an inbound request and sending a response.
    InboundFailure {
        request_id: RequestId,
        peer: PeerId,
        failure: InboundFailure,
    },
    /// The response for a previously sent request was received.
    ReceivedResponse {
        request_id: RequestId,
        peer: PeerId,
        /// Response from the remote peer.
        response: Rs,
    },
    /// A failure occurred in the context of sending an outbound request and receiving a response.
    OutboundFailure {
        request_id: RequestId,
        peer: PeerId,
        failure: OutboundFailure,
    },
}

/// The Relay protocol is not supported.
#[derive(Debug)]
pub struct RelayNotSupported;

/// Possible failures occurring in the context of sending an outbound request and receiving the response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundFailure {
    /// The request timed out before a response was received.
    ///
    /// It is not known whether the request may have been
    /// received (and processed) by the remote peer.
    Timeout,
    /// The request could not be sent because a dialing attempt failed.
    DialFailure,
    /// The connection closed before a response was received.
    ///
    /// It is not known whether the request may have been
    /// received (and processed) by the remote peer.
    ConnectionClosed,
    /// The remote supports none of the requested protocols.
    UnsupportedProtocols,
    /// `StrongholdP2p` was shut down before a response was received.
    Shutdown,
}

impl fmt::Display for OutboundFailure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OutboundFailure::Timeout => write!(f, "Timeout while waiting for a response"),
            OutboundFailure::ConnectionClosed => write!(f, "Connection was closed before a response was received"),
            OutboundFailure::UnsupportedProtocols => {
                write!(f, "The remote supports none of the requested protocols")
            }
            OutboundFailure::DialFailure => write!(f, "Failed to dial the requested peer"),
            OutboundFailure::Shutdown => write!(f, "The local peer was shut down before a response was received."),
        }
    }
}

impl std::error::Error for OutboundFailure {}

/// Possible failures occurring in the context of receiving an inbound request and sending a response.
///
/// **Note**: If the firewall is configured to block per se all requests from the remote peer, the protocol for inbound
/// requests will not be supported in the first place, and inbound requests are rejected without emitting a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InboundFailure {
    /// The inbound request timed out, either while reading the
    /// incoming request or before a response is sent through [`RequestMessage.response_tx`].
    Timeout,
    /// The local firewall blocked the request.
    NotPermitted,
    /// The connection closed before a response could be send.
    ConnectionClosed,
}

impl fmt::Display for InboundFailure {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            InboundFailure::Timeout => write!(f, "Timeout while receiving request"),
            InboundFailure::NotPermitted => write!(f, "The firewall blocked the inbound request"),
            InboundFailure::ConnectionClosed => {
                write!(f, "The connection closed directly after the request was received")
            }
        }
    }
}

impl std::error::Error for InboundFailure {}

#[cfg(test)]
mod test {
    use core::panic;

    use super::*;
    use crate::firewall::permissions::{PermissionValue, RequestPermissions, VariantPermission};
    use futures::{channel::mpsc, StreamExt};
    use libp2p::{
        core::{identity, upgrade, PeerId, Transport},
        mdns::{Mdns, MdnsConfig},
        noise::{Keypair as NoiseKeypair, NoiseConfig, X25519Spec},
        relay::v1::{new_transport_and_behaviour, RelayConfig},
        swarm::{Swarm, SwarmBuilder, SwarmEvent},
        tcp::TokioTcpConfig,
        yamux::YamuxConfig,
    };
    use serde::{Deserialize, Serialize};

    // Exercises a simple ping protocol.
    #[tokio::test]
    async fn ping_protocol() {
        let ping = Ping("ping".to_string().into_bytes());
        let pong = Pong("pong".to_string().into_bytes());
        let expected_ping = ping.clone();

        let (peer1_id, mut swarm1) = init_swarm().await;
        let (peer2_id, mut swarm2) = init_swarm().await;

        let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        swarm1.listen_on(addr).unwrap();

        let addr = match swarm1.select_next_some().await {
            SwarmEvent::NewListenAddr { address, .. } => address,
            _ => panic!("Peer1: Unexpected event"),
        };
        swarm2.behaviour_mut().add_address(peer1_id, addr.clone());

        let mut request_id = swarm2.behaviour_mut().send_request(peer1_id, ping.clone());

        let num_pings = 100;
        let mut count = 0u8;

        loop {
            futures::select! {
                event = swarm1.select_next_some() => match event {
                    SwarmEvent::Behaviour(BehaviourEvent::ReceivedRequest {
                        peer,
                        response_tx,
                        request,
                        ..
                    }) => {
                        assert_eq!(&request, &expected_ping);
                        assert_eq!(&peer, &peer2_id);
                        response_tx.send(pong.clone()).unwrap();
                    }
                    SwarmEvent::Behaviour(e) => panic!("Peer1: Unexpected event: {:?}", e),
                    _ => {}
                },
                event = swarm2.select_next_some() => match event {
                    SwarmEvent::Behaviour(BehaviourEvent::ReceivedResponse {
                            request_id: rq_id,
                            peer,
                            ..
                        }) => {
                            assert_eq!(request_id, rq_id);
                            assert_eq!(peer, peer1_id);
                            count += 1;
                            if count < num_pings {
                                request_id = swarm2.behaviour_mut().send_request(peer1_id, ping.clone());
                            } else {
                                break;
                            }
                        }
                        SwarmEvent::Behaviour(other) => panic!("Peer2: Unexpected event: {:?}.", other),
                        _ => {}
                }
            }
        }
    }

    #[tokio::test]
    async fn emits_inbound_connection_closed_failure() {
        let ping = Ping("ping".to_string().into_bytes());
        let pong = Pong("pong".to_string().into_bytes());

        let (peer1_id, mut swarm1) = init_swarm().await;
        let (peer2_id, mut swarm2) = init_swarm().await;

        let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        swarm1.listen_on(addr).unwrap();

        let addr1 = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm1.select_next_some().await {
                break address;
            }
        };

        swarm2.behaviour_mut().add_address(peer1_id, addr1.clone());
        swarm2.behaviour_mut().send_request(peer1_id, ping.clone());

        // Wait for swarm 1 to receive request by swarm 2.
        let response_tx = loop {
            futures::select_biased!(
                event = swarm2.select_next_some() => {
                    if let SwarmEvent::Behaviour(..) =  event {
                        panic!("Peer2: Unexpected event: {:?}", event)
                    }
                }
                event = swarm1.select_next_some() => match event {
                    SwarmEvent::Behaviour(BehaviourEvent::ReceivedRequest{
                        peer,
                        response_tx,
                        request,
                        ..
                    }) => {
                    assert_eq!(&request, &ping);
                    assert_eq!(&peer, &peer2_id);
                    break response_tx
                    },
                    SwarmEvent::Behaviour(e) => panic!("Peer1: Unexpected event: {:?}", e),
                    _ => {}
                },
            )
        };

        // Drop swarm 2 in order for the connection between swarm 1 and 2 to close.
        drop(swarm2);

        match swarm1.select_next_some().await {
            SwarmEvent::ConnectionClosed { peer_id, .. } if peer_id == peer2_id => {
                assert!(response_tx.send(pong).is_err());
            }
            e => panic!("Peer1: Unexpected event: {:?}", e),
        }
    }

    /// We expect the substream to be properly closed when response channel is dropped.
    /// Since the ping protocol used here expects a response, the sender considers this
    /// early close as a protocol violation which results in the connection being closed.
    /// If the substream were not properly closed when dropped, the sender would instead
    /// run into a timeout waiting for the response.
    #[tokio::test]
    async fn emits_inbound_connection_closed_if_channel_is_dropped() {
        let ping = Ping("ping".to_string().into_bytes());

        let (peer1_id, mut swarm1) = init_swarm().await;
        let (peer2_id, mut swarm2) = init_swarm().await;

        let addr = "/ip4/127.0.0.1/tcp/0".parse().unwrap();
        swarm1.listen_on(addr).unwrap();

        let addr1 = loop {
            if let SwarmEvent::NewListenAddr { address, .. } = swarm1.select_next_some().await {
                break address;
            }
        };

        swarm2.behaviour_mut().add_address(peer1_id, addr1.clone());
        let request_id = swarm2.behaviour_mut().send_request(peer1_id, ping.clone());

        loop {
            futures::select_biased!(
                event = swarm2.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(BehaviourEvent::OutboundFailure {
                            request_id: rq_id,
                            peer,
                            failure,
                        }) => {
                            assert_eq!(request_id, rq_id);
                            assert_eq!(peer, peer1_id);
                            assert_eq!(failure, OutboundFailure::ConnectionClosed);
                            break;
                        }
                        SwarmEvent::Behaviour(other) => panic!("Peer2: unexpected event: {:?}", other),
                        _ => {}
                    }
                }
                event = swarm1.select_next_some() => match event {
                    SwarmEvent::Behaviour(BehaviourEvent::ReceivedRequest{
                        peer,
                        response_tx,
                        request,
                        ..
                    }) => {
                        assert_eq!(&request, &ping);
                        assert_eq!(&peer, &peer2_id);
                        drop(response_tx);
                        continue;
                    },
                    SwarmEvent::Behaviour(e) => panic!("Peer1: Unexpected event: {:?}", e),
                    _ => {}
                },
            )
        }
    }

    async fn init_swarm() -> (PeerId, Swarm<NetworkBehaviour<Ping, Pong>>) {
        let id_keys = identity::Keypair::generate_ed25519();
        let peer = id_keys.public().to_peer_id();
        let noise_keys = NoiseKeypair::<X25519Spec>::new().into_authentic(&id_keys).unwrap();
        let transport = TokioTcpConfig::new();

        let (transport, relay_behaviour) = new_transport_and_behaviour(RelayConfig::default(), transport);
        let transport = transport
            .upgrade(upgrade::Version::V1)
            .authenticate(NoiseConfig::xx(noise_keys).into_authenticated())
            .multiplex(YamuxConfig::default())
            .boxed();

        let mdns = Mdns::new(MdnsConfig::default())
            .await
            .expect("Failed to create mdns behaviour.");
        let (dummy_tx, _) = mpsc::channel(10);
        let behaviour = NetworkBehaviour::new(
            ConfigConfig::default(),
            Some(mdns),
            Some(relay_behaviour),
            dummy_tx,
            FirewallRules::allow_all(),
            None,
        );
        let builder = SwarmBuilder::new(transport, behaviour, peer).executor(Box::new(|fut| {
            tokio::spawn(fut);
        }));
        (peer, builder.build())
    }

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RequestPermissions)]
    struct Ping(Vec<u8>);
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, RequestPermissions)]
    struct Pong(Vec<u8>);
}
