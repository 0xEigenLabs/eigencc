use crate::msgs::enums::{ContentType, HandshakeType};
use crate::msgs::enums::{ProtocolVersion, AlertDescription};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::base::{Payload, PayloadU8};
use crate::msgs::handshake::{HandshakePayload, HandshakeMessagePayload};
use crate::msgs::handshake::DecomposedSignatureScheme;
use crate::msgs::handshake::ServerKeyExchangePayload;
use crate::msgs::handshake::DigitallySignedStruct;
use crate::msgs::enums::ClientCertificateType;
use crate::msgs::codec::Codec;
use crate::msgs::persist;
use crate::msgs::ccs::ChangeCipherSpecPayload;
use crate::client::ClientSessionImpl;
use crate::session::SessionSecrets;
use crate::suites;
use crate::verify;
use crate::ticketer;
#[cfg(feature = "logging")]
use crate::log::{debug, trace, warn};
use crate::error::TLSError;
use crate::handshake::{check_message, check_handshake_message};

use crate::client::common::{ServerCertDetails, ServerKXDetails, HandshakeDetails};
use crate::client::common::{ReceivedTicketDetails, ClientAuthDetails};
use crate::client::hs;

use std::mem;
use ring::constant_time;

pub struct ExpectCertificate {
    pub handshake: HandshakeDetails,
    pub server_cert: ServerCertDetails,
    pub may_send_cert_status: bool,
    pub must_issue_new_ticket: bool,
}

impl ExpectCertificate {
    fn into_expect_certificate_status_or_server_kx(self) -> hs::NextState {
        Box::new(ExpectCertificateStatusOrServerKX {
            handshake: self.handshake,
            server_cert: self.server_cert,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }

    fn into_expect_server_kx(self) -> hs::NextState {
        Box::new(ExpectServerKX {
            handshake: self.handshake,
            server_cert: self.server_cert,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

impl hs::State for ExpectCertificate {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::Certificate])
    }

    fn handle(mut self: Box<Self>, _sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        let cert_chain = extract_handshake!(m, HandshakePayload::Certificate).unwrap();
        self.handshake.transcript.add_message(&m);

        self.server_cert.cert_chain = cert_chain.clone();

        if self.may_send_cert_status {
            Ok(self.into_expect_certificate_status_or_server_kx())
        } else {
            Ok(self.into_expect_server_kx())
        }
    }
}

struct ExpectCertificateStatus {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    must_issue_new_ticket: bool,
}

impl ExpectCertificateStatus {
    fn into_expect_server_kx(self) -> hs::NextState {
        Box::new(ExpectServerKX {
            handshake: self.handshake,
            server_cert: self.server_cert,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

impl hs::State for ExpectCertificateStatus {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::CertificateStatus])
    }

    fn handle(mut self: Box<Self>, _sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        self.handshake.transcript.add_message(&m);
        let mut status = extract_handshake_mut!(m, HandshakePayload::CertificateStatus).unwrap();

        self.server_cert.ocsp_response = status.take_ocsp_response();
        debug!("Server stapled OCSP response is {:?}", self.server_cert.ocsp_response);
        Ok(self.into_expect_server_kx())
    }
}

struct ExpectCertificateStatusOrServerKX {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    must_issue_new_ticket: bool,
}

impl ExpectCertificateStatusOrServerKX {
    fn into_expect_server_kx(self) -> hs::NextState {
        Box::new(ExpectServerKX {
            handshake: self.handshake,
            server_cert: self.server_cert,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }

    fn into_expect_certificate_status(self) -> hs::NextState {
        Box::new(ExpectCertificateStatus {
            handshake: self.handshake,
            server_cert: self.server_cert,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

impl hs::State for ExpectCertificateStatusOrServerKX {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m,
                                &[HandshakeType::ServerKeyExchange,
                                  HandshakeType::CertificateStatus])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        if m.is_handshake_type(HandshakeType::ServerKeyExchange) {
            self.into_expect_server_kx().handle(sess, m)
        } else {
            self.into_expect_certificate_status().handle(sess, m)
        }
    }
}

struct ExpectServerKX {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    must_issue_new_ticket: bool,
}

impl ExpectServerKX {
    fn into_expect_server_done_or_certreq(self, skx: ServerKXDetails) -> hs::NextState {
        Box::new(ExpectServerDoneOrCertReq {
            handshake: self.handshake,
            server_cert: self.server_cert,
            server_kx: skx,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

impl hs::State for ExpectServerKX {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::ServerKeyExchange])
    }

    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        let opaque_kx = extract_handshake!(m, HandshakePayload::ServerKeyExchange).unwrap();
        let maybe_decoded_kx = opaque_kx.unwrap_given_kxa(&sess.common.get_suite_assert().kx);
        self.handshake.transcript.add_message(&m);

        if maybe_decoded_kx.is_none() {
            sess.common.send_fatal_alert(AlertDescription::DecodeError);
            return Err(TLSError::CorruptMessagePayload(ContentType::Handshake));
        }

        let decoded_kx = maybe_decoded_kx.unwrap();

        // Save the signature and signed parameters for later verification.
        let mut kx_params = Vec::new();
        decoded_kx.encode_params(&mut kx_params);
        let skx = ServerKXDetails::new(kx_params, decoded_kx.get_sig().unwrap());

        #[cfg_attr(not(feature = "logging"), allow(unused_variables))]
        {
            if let ServerKeyExchangePayload::ECDHE(ecdhe) = decoded_kx {
                debug!("ECDHE curve is {:?}", ecdhe.params.curve_params);
            }
        }

        Ok(self.into_expect_server_done_or_certreq(skx))
    }
}

fn emit_certificate(handshake: &mut HandshakeDetails,
                    client_auth: &mut ClientAuthDetails,
                    sess: &mut ClientSessionImpl) {
    let chosen_cert = client_auth.cert.take();

    let cert = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Certificate,
            payload: HandshakePayload::Certificate(chosen_cert.unwrap_or_else(Vec::new)),
        }),
    };

    handshake.transcript.add_message(&cert);
    sess.common.send_msg(cert, false);
}

fn emit_clientkx(handshake: &mut HandshakeDetails,
                 sess: &mut ClientSessionImpl,
                 kxd: &suites::KeyExchangeResult) {
    let mut buf = Vec::new();
    let ecpoint = PayloadU8::new(Vec::from(kxd.pubkey.as_ref()));
    ecpoint.encode(&mut buf);
    let pubkey = Payload::new(buf);

    let ckx = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::ClientKeyExchange,
            payload: HandshakePayload::ClientKeyExchange(pubkey),
        }),
    };

    handshake.transcript.add_message(&ckx);
    sess.common.send_msg(ckx, false);
}

fn emit_certverify(handshake: &mut HandshakeDetails,
                   client_auth: &mut ClientAuthDetails,
                   sess: &mut ClientSessionImpl) -> Result<(), TLSError> {
    if client_auth.signer.is_none() {
        trace!("Not sending CertificateVerify, no key");
        handshake.transcript.abandon_client_auth();
        return Ok(());
    }

    let message = handshake.transcript.take_handshake_buf();
    let signer = client_auth.signer.take().unwrap();
    let scheme = signer.get_scheme();
    let sig = signer.sign(&message)?;
    let body = DigitallySignedStruct::new(scheme, sig);

    let m = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::CertificateVerify,
            payload: HandshakePayload::CertificateVerify(body),
        }),
    };

    handshake.transcript.add_message(&m);
    sess.common.send_msg(m, false);
    Ok(())
}

fn emit_ccs(sess: &mut ClientSessionImpl) {
    let ccs = Message {
        typ: ContentType::ChangeCipherSpec,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::ChangeCipherSpec(ChangeCipherSpecPayload {}),
    };

    sess.common.send_msg(ccs, false);
    sess.common.we_now_encrypting();
}

fn emit_finished(handshake: &mut HandshakeDetails,
                 sess: &mut ClientSessionImpl) {
    let vh = handshake.transcript.get_current_hash();
    let verify_data = sess.common.secrets
        .as_ref()
        .unwrap()
        .client_verify_data(&vh);
    let verify_data_payload = Payload::new(verify_data);

    let f = Message {
        typ: ContentType::Handshake,
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake(HandshakeMessagePayload {
            typ: HandshakeType::Finished,
            payload: HandshakePayload::Finished(verify_data_payload),
        }),
    };

    handshake.transcript.add_message(&f);
    sess.common.send_msg(f, true);
}

// --- Either a CertificateRequest, or a ServerHelloDone. ---
// Existence of the CertificateRequest tells us the server is asking for
// client auth.  Otherwise we go straight to ServerHelloDone.
struct ExpectCertificateRequest {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    server_kx: ServerKXDetails,
    must_issue_new_ticket: bool,
}

impl ExpectCertificateRequest {
    fn into_expect_server_done(self, client_auth: ClientAuthDetails) -> hs::NextState {
        Box::new(ExpectServerDone {
            handshake: self.handshake,
            server_cert: self.server_cert,
            server_kx: self.server_kx,
            client_auth: Some(client_auth),
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

impl hs::State for ExpectCertificateRequest {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::CertificateRequest])
    }

    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        let certreq = extract_handshake!(m, HandshakePayload::CertificateRequest).unwrap();
        self.handshake.transcript.add_message(&m);
        debug!("Got CertificateRequest {:?}", certreq);

        let mut client_auth = ClientAuthDetails::new();

        // The RFC jovially describes the design here as 'somewhat complicated'
        // and 'somewhat underspecified'.  So thanks for that.

        // We only support RSA signing at the moment.  If you don't support that,
        // we're not doing client auth.
        if !certreq.certtypes.contains(&ClientCertificateType::RSASign) {
            warn!("Server asked for client auth but without RSASign");
            return Ok(self.into_expect_server_done(client_auth));
        }

        let canames = certreq.canames
            .iter()
            .map(|p| p.0.as_slice())
            .collect::<Vec<&[u8]>>();
        let maybe_certkey =
            sess.config.client_auth_cert_resolver.resolve(&canames, &certreq.sigschemes);

        if let Some(mut certkey) = maybe_certkey {
            debug!("Attempting client auth");
            let maybe_signer = certkey.key.choose_scheme(&certreq.sigschemes);
            client_auth.cert = Some(certkey.take_cert());
            client_auth.signer = maybe_signer;
        } else {
            debug!("Client auth requested but no cert/sigscheme available");
        }

        Ok(self.into_expect_server_done(client_auth))
    }
}

struct ExpectServerDoneOrCertReq {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    server_kx: ServerKXDetails,
    must_issue_new_ticket: bool,
}

impl ExpectServerDoneOrCertReq {
    fn into_expect_certificate_req(self) -> hs::NextState {
        Box::new(ExpectCertificateRequest {
            handshake: self.handshake,
            server_cert: self.server_cert,
            server_kx: self.server_kx,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }

    fn into_expect_server_done(self) -> hs::NextState {
        Box::new(ExpectServerDone {
            handshake: self.handshake,
            server_cert: self.server_cert,
            server_kx: self.server_kx,
            client_auth: None,
            must_issue_new_ticket: self.must_issue_new_ticket,
        })
    }
}

impl hs::State for ExpectServerDoneOrCertReq {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m,
                                &[HandshakeType::CertificateRequest,
                                  HandshakeType::ServerHelloDone])
    }

    fn handle(mut self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        if extract_handshake!(m, HandshakePayload::CertificateRequest).is_some() {
            self.into_expect_certificate_req().handle(sess, m)
        } else {
            self.handshake.transcript.abandon_client_auth();
            self.into_expect_server_done().handle(sess, m)
        }
    }
}


struct ExpectServerDone {
    handshake: HandshakeDetails,
    server_cert: ServerCertDetails,
    server_kx: ServerKXDetails,
    client_auth: Option<ClientAuthDetails>,
    must_issue_new_ticket: bool,
}

impl ExpectServerDone {
    fn into_expect_new_ticket(self,
                                    certv: verify::ServerCertVerified,
                                    sigv: verify::HandshakeSignatureValid) -> hs::NextState {
        Box::new(ExpectNewTicket {
            handshake: self.handshake,
            resuming: false,
            cert_verified: certv,
            sig_verified: sigv,
        })
    }

    fn into_expect_ccs(self,
                             certv: verify::ServerCertVerified,
                             sigv: verify::HandshakeSignatureValid) -> hs::NextState {
        Box::new(ExpectCCS {
            handshake: self.handshake,
            ticket: ReceivedTicketDetails::new(),
            resuming: false,
            cert_verified: certv,
            sig_verified: sigv,
        })
    }
}

impl hs::State for ExpectServerDone {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::ServerHelloDone])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        let mut st = *self;
        st.handshake.transcript.add_message(&m);

        debug!("Server cert is {:?}", st.server_cert.cert_chain);
        debug!("Server DNS name is {:?}", st.handshake.dns_name);

        // 1. Verify the cert chain.
        // 2. Verify any SCTs provided with the certificate.
        // 3. Verify that the top certificate signed their kx.
        // 4. If doing client auth, send our Certificate.
        // 5. Complete the key exchange:
        //    a) generate our kx pair
        //    b) emit a ClientKeyExchange containing it
        //    c) if doing client auth, emit a CertificateVerify
        //    d) emit a CCS
        //    e) derive the shared keys, and start encryption
        // 6. emit a Finished, our first encrypted message under the new keys.

        // 1.
        if st.server_cert.cert_chain.is_empty() {
            return Err(TLSError::NoCertificatesPresented);
        }

        let certv = sess.config
            .get_verifier()
            .verify_server_cert(&sess.config.root_store,
                                &st.server_cert.cert_chain,
                                st.handshake.dns_name.as_ref(),
                                &st.server_cert.ocsp_response)
            .map_err(|err| hs::send_cert_error_alert(sess, err))?;

        // 2. Verify any included SCTs.
        match (st.server_cert.scts.as_ref(), sess.config.ct_logs) {
            (Some(scts), Some(logs)) => {
                verify::verify_scts(&st.server_cert.cert_chain[0],
                                    scts,
                                    logs)?;
            }
            (_, _) => {}
        }

        // 3.
        // Build up the contents of the signed message.
        // It's ClientHello.random || ServerHello.random || ServerKeyExchange.params
        let sigv = {
            let mut message = Vec::new();
            message.extend_from_slice(&st.handshake.randoms.client);
            message.extend_from_slice(&st.handshake.randoms.server);
            message.extend_from_slice(&st.server_kx.kx_params);

            // Check the signature is compatible with the ciphersuite.
            let sig = &st.server_kx.kx_sig;
            let scs = sess.common.get_suite_assert();
            if scs.sign != sig.scheme.sign() {
                let error_message =
                    format!("peer signed kx with wrong algorithm (got {:?} expect {:?})",
                                      sig.scheme.sign(), scs.sign);
                return Err(TLSError::PeerMisbehavedError(error_message));
            }

            verify::verify_signed_struct(&message,
                                         &st.server_cert.cert_chain[0],
                                         sig)
                .map_err(|err| hs::send_cert_error_alert(sess, err))?
        };
        sess.server_cert_chain = st.server_cert.take_chain();

        // 4.
        if st.client_auth.is_some() {
            emit_certificate(&mut st.handshake,
                             st.client_auth.as_mut().unwrap(),
                             sess);
        }

        // 5a.
        let kxd = sess.common.get_suite_assert()
            .do_client_kx(&st.server_kx.kx_params)
            .ok_or_else(|| TLSError::PeerMisbehavedError("key exchange failed".to_string()))?;

        // 5b.
        emit_clientkx(&mut st.handshake, sess, &kxd);
        // nb. EMS handshake hash only runs up to ClientKeyExchange.
        let handshake_hash = st.handshake.transcript.get_current_hash();

        // 5c.
        if st.client_auth.is_some() {
            emit_certverify(&mut st.handshake,
                            st.client_auth.as_mut().unwrap(),
                            sess)?;
        }

        // 5d.
        emit_ccs(sess);

        // 5e. Now commit secrets.
        let hashalg = sess.common.get_suite_assert().get_hash();
        let secrets = if st.handshake.using_ems {
            SessionSecrets::new_ems(&st.handshake.randoms,
                                    &handshake_hash,
                                    hashalg,
                                    &kxd.premaster_secret)
        } else {
            SessionSecrets::new(&st.handshake.randoms,
                                hashalg,
                                &kxd.premaster_secret)
        };
        sess.config.key_log.log("CLIENT_RANDOM",
                                &secrets.randoms.client,
                                &secrets.master_secret);
        sess.common.start_encryption_tls12(secrets);

        // 6.
        emit_finished(&mut st.handshake, sess);

        if st.must_issue_new_ticket {
            Ok(st.into_expect_new_ticket(certv, sigv))
        } else {
            Ok(st.into_expect_ccs(certv, sigv))
        }
    }
}

// -- Waiting for their CCS --
pub struct ExpectCCS {
    pub handshake: HandshakeDetails,
    pub ticket: ReceivedTicketDetails,
    pub resuming: bool,
    pub cert_verified: verify::ServerCertVerified,
    pub sig_verified: verify::HandshakeSignatureValid,
}

impl ExpectCCS {
    fn into_expect_finished(self) -> hs::NextState {
        Box::new(ExpectFinished {
            handshake: self.handshake,
            ticket: self.ticket,
            resuming: self.resuming,
            cert_verified: self.cert_verified,
            sig_verified: self.sig_verified,
        })
    }
}

impl hs::State for ExpectCCS {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_message(m, &[ContentType::ChangeCipherSpec], &[])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, _m: Message) -> hs::NextStateOrError {
        // CCS should not be received interleaved with fragmented handshake-level
        // message.
        if !sess.common.handshake_joiner.is_empty() {
            warn!("CCS received interleaved with fragmented handshake");
            return Err(TLSError::InappropriateMessage {
                expect_types: vec![ ContentType::Handshake ],
                got_type: ContentType::ChangeCipherSpec,
            });
        }

        // nb. msgs layer validates trivial contents of CCS
        sess.common.peer_now_encrypting();

        Ok(self.into_expect_finished())
    }
}

pub struct ExpectNewTicket {
    pub handshake: HandshakeDetails,
    pub resuming: bool,
    pub cert_verified: verify::ServerCertVerified,
    pub sig_verified: verify::HandshakeSignatureValid,
}

impl ExpectNewTicket {
    fn into_expect_ccs(self, ticket: ReceivedTicketDetails) -> hs::NextState {
        Box::new(ExpectCCS {
            handshake: self.handshake,
            ticket,
            resuming: self.resuming,
            cert_verified: self.cert_verified,
            sig_verified: self.sig_verified,
        })
    }
}

impl hs::State for ExpectNewTicket {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::NewSessionTicket])
    }

    fn handle(mut self: Box<Self>, _sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        self.handshake.transcript.add_message(&m);

        let nst = extract_handshake_mut!(m, HandshakePayload::NewSessionTicket).unwrap();
        let recvd = ReceivedTicketDetails::from(nst.ticket.0, nst.lifetime_hint);
        Ok(self.into_expect_ccs(recvd))
    }
}

// -- Waiting for their finished --
fn save_session(handshake: &mut HandshakeDetails,
                recvd_ticket: &mut ReceivedTicketDetails,
                sess: &mut ClientSessionImpl) {
    // Save a ticket.  If we got a new ticket, save that.  Otherwise, save the
    // original ticket again.
    let mut ticket = mem::replace(&mut recvd_ticket.new_ticket, Vec::new());
    if ticket.is_empty() && handshake.resuming_session.is_some() {
        ticket = handshake.resuming_session.as_mut().unwrap().take_ticket();
    }

    if handshake.session_id.is_empty() && ticket.is_empty() {
        debug!("Session not saved: server didn't allocate id or ticket");
        return;
    }

    let key = persist::ClientSessionKey::session_for_dns_name(handshake.dns_name.as_ref());

    let scs = sess.common.get_suite_assert();
    let master_secret = sess.common.secrets.as_ref().unwrap().get_master_secret();
    let version = sess.get_protocol_version().unwrap();
    let mut value = persist::ClientSessionValue::new(version,
                                                     scs.suite,
                                                     &handshake.session_id,
                                                     ticket,
                                                     master_secret);
    value.set_times(ticketer::timebase(),
                    recvd_ticket.new_ticket_lifetime,
                    0);
    if handshake.using_ems {
        value.set_extended_ms_used();
    }

    let worked = sess.config.session_persistence.put(key.get_encoding(),
                                                     value.get_encoding());

    if worked {
        debug!("Session saved");
    } else {
        debug!("Session not saved");
    }
}

struct ExpectFinished {
    handshake: HandshakeDetails,
    ticket: ReceivedTicketDetails,
    resuming: bool,
    cert_verified: verify::ServerCertVerified,
    sig_verified: verify::HandshakeSignatureValid,
}

impl ExpectFinished {
    fn into_expect_traffic(self, fin: verify::FinishedMessageVerified) -> hs::NextState {
        Box::new(ExpectTraffic {
            _cert_verified: self.cert_verified,
            _sig_verified: self.sig_verified,
            _fin_verified: fin,
        })
    }
}

impl hs::State for ExpectFinished {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_handshake_message(m, &[HandshakeType::Finished])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, m: Message) -> hs::NextStateOrError {
        let mut st = *self;
        let finished = extract_handshake!(m, HandshakePayload::Finished).unwrap();

        // Work out what verify_data we expect.
        let vh = st.handshake.transcript.get_current_hash();
        let expect_verify_data = sess.common.secrets
            .as_ref()
            .unwrap()
            .server_verify_data(&vh);

        // Constant-time verification of this is relatively unimportant: they only
        // get one chance.  But it can't hurt.
        let fin = constant_time::verify_slices_are_equal(&expect_verify_data, &finished.0)
            .map_err(|_| {
                     sess.common.send_fatal_alert(AlertDescription::DecryptError);
                     TLSError::DecryptError
                     })
            .map(|_| verify::FinishedMessageVerified::assertion())?;

        // Hash this message too.
        st.handshake.transcript.add_message(&m);

        save_session(&mut st.handshake,
                     &mut st.ticket,
                     sess);

        if st.resuming {
            emit_ccs(sess);
            emit_finished(&mut st.handshake, sess);
        }

        sess.common.we_now_encrypting();
        sess.common.start_traffic();
        Ok(st.into_expect_traffic(fin))
    }
}

// -- Traffic transit state --
struct ExpectTraffic {
    _cert_verified: verify::ServerCertVerified,
    _sig_verified: verify::HandshakeSignatureValid,
    _fin_verified: verify::FinishedMessageVerified,
}

impl hs::State for ExpectTraffic {
    fn check_message(&self, m: &Message) -> Result<(), TLSError> {
        check_message(m, &[ContentType::ApplicationData], &[])
    }

    fn handle(self: Box<Self>, sess: &mut ClientSessionImpl, mut m: Message) -> hs::NextStateOrError {
        sess.common.take_received_plaintext(m.take_opaque_payload().unwrap());
        Ok(self)
    }
}
