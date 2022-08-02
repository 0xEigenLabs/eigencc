// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![allow(dead_code)]

use sgx_trts::libc::{c_int, c_uint, c_void};
use core::cmp;
use core::fmt;
use core::mem;
use core::ptr;
use core::convert::{TryFrom, TryInto};
use crate::ffi::CString;
use crate::io::{self, Error, ErrorKind, IoSlice, IoSliceMut};
use crate::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use crate::sys::net::{cvt, cvt_gai, cvt_r, init, wrlen_t, Socket};
use crate::sys_common::{AsInner, FromInner, IntoInner};
use crate::time::Duration;

////////////////////////////////////////////////////////////////////////////////
// sockaddr and misc bindings
////////////////////////////////////////////////////////////////////////////////

pub fn setsockopt<T>(sock: &Socket, opt: c_int, val: c_int, payload: T) -> io::Result<()> {
    unsafe {
        let payload = &payload as *const T as *const c_void;
        cvt(libc::setsockopt(
            *sock.as_inner(),
            opt,
            val,
            payload,
            mem::size_of::<T>() as libc::socklen_t,
        ))?;
        Ok(())
    }
}

pub fn getsockopt<T: Copy>(sock: &Socket, opt: c_int, val: c_int) -> io::Result<T> {
    unsafe {
        let mut slot: T = mem::zeroed();
        let mut len = mem::size_of::<T>() as libc::socklen_t;
        cvt(libc::getsockopt(
            *sock.as_inner(),
            opt,
            val,
            &mut slot as *mut _ as *mut _,
            &mut len,
        ))?;
        assert_eq!(len as usize, mem::size_of::<T>());
        Ok(slot)
    }
}

fn sockname<F>(f: F) -> io::Result<SocketAddr>
where
    F: FnOnce(*mut libc::sockaddr, *mut libc::socklen_t) -> c_int,
{
    unsafe {
        let mut storage: libc::sockaddr_storage = mem::zeroed();
        let mut len = mem::size_of_val(&storage) as libc::socklen_t;
        cvt(f(&mut storage as *mut _ as *mut _, &mut len))?;
        sockaddr_to_addr(&storage, len as usize)
    }
}

pub fn sockaddr_to_addr(storage: &libc::sockaddr_storage, len: usize) -> io::Result<SocketAddr> {
    match storage.ss_family as c_int {
        libc::AF_INET => {
            assert!(len as usize >= mem::size_of::<libc::sockaddr_in>());
            Ok(SocketAddr::V4(FromInner::from_inner(unsafe {
                *(storage as *const _ as *const libc::sockaddr_in)
            })))
        }
        libc::AF_INET6 => {
            assert!(len as usize >= mem::size_of::<libc::sockaddr_in6>());
            Ok(SocketAddr::V6(FromInner::from_inner(unsafe {
                *(storage as *const _ as *const libc::sockaddr_in6)
            })))
        }
        _ => Err(Error::new(ErrorKind::InvalidInput, "invalid argument")),
    }
}

fn to_ipv6mr_interface(value: u32) -> c_uint {
    value as c_uint
}

////////////////////////////////////////////////////////////////////////////////
// get_host_addresses
////////////////////////////////////////////////////////////////////////////////

pub struct LookupHost {
    original: *mut libc::addrinfo,
    cur: *mut libc::addrinfo,
    port: u16,
}

impl LookupHost {
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Iterator for LookupHost {
    type Item = SocketAddr;
    fn next(&mut self) -> Option<SocketAddr> {
        loop {
            unsafe {
                let cur = self.cur.as_ref()?;
                self.cur = cur.ai_next;
                match sockaddr_to_addr(mem::transmute(cur.ai_addr), cur.ai_addrlen as usize) {
                    Ok(addr) => return Some(addr),
                    Err(_) => continue,
                }
            }
        }
    }
}

unsafe impl Sync for LookupHost {}
unsafe impl Send for LookupHost {}

impl Drop for LookupHost {
    fn drop(&mut self) {
        unsafe { libc::freeaddrinfo(self.original) }
    }
}

impl TryFrom<&str> for LookupHost {
    type Error = io::Error;

    fn try_from(s: &str) -> io::Result<LookupHost> {
        macro_rules! try_opt {
            ($e:expr, $msg:expr) => {
                match $e {
                    Some(r) => r,
                    None => return Err(io::Error::new(io::ErrorKind::InvalidInput, $msg)),
                }
            };
        }

        // split the string by ':' and convert the second part to u16
        let mut parts_iter = s.rsplitn(2, ':');
        let port_str = try_opt!(parts_iter.next(), "invalid socket address");
        let host = try_opt!(parts_iter.next(), "invalid socket address");
        let port: u16 = try_opt!(port_str.parse().ok(), "invalid port value");

        (host, port).try_into()
    }
}

impl<'a> TryFrom<(&'a str, u16)> for LookupHost {
    type Error = io::Error;

    fn try_from((host, port): (&'a str, u16)) -> io::Result<LookupHost> {
        init();

        let c_host = CString::new(host)?;
        let mut hints: libc::addrinfo = unsafe { mem::zeroed() };
        hints.ai_socktype = libc::SOCK_STREAM;
        let mut res = ptr::null_mut();
        unsafe {
            cvt_gai(libc::getaddrinfo(c_host.as_ptr(), ptr::null(), &hints, &mut res))
                .map(|_| LookupHost { original: res, cur: res, port })
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// TCP streams
////////////////////////////////////////////////////////////////////////////////

pub struct TcpStream {
    inner: Socket,
}

impl TcpStream {
    pub fn new(sockfd: c_int) -> io::Result<TcpStream> {
        let sock = Socket::new(sockfd)?;
        Ok(TcpStream { inner: sock })
    }

    pub fn new_v4() -> io::Result<TcpStream> {
        let sock = Socket::new_raw(libc::AF_INET, libc::SOCK_STREAM)?;
        Ok(TcpStream { inner: sock })
    }

    pub fn new_v6() -> io::Result<TcpStream> {
        let sock = Socket::new_raw(libc::AF_INET6, libc::SOCK_STREAM)?;
        Ok(TcpStream { inner: sock })
    }

    pub fn raw(&self) -> c_int {
        self.inner.raw()
    }

    pub fn into_raw(self) -> c_int {
        self.inner.into_raw()
    }

    pub fn connect(addr: io::Result<&SocketAddr>) -> io::Result<TcpStream> {
        let addr = addr?;

        init();

        let sock = Socket::new_socket_addr_type(addr, libc::SOCK_STREAM)?;
        let (addrp, len) = addr.into_inner();
        cvt_r(|| unsafe { libc::connect(*sock.as_inner(), addrp, len) })?;
        Ok(TcpStream { inner: sock })
    }

    pub fn connect_socket(&self, addr: io::Result<&SocketAddr>) -> io::Result<()> {
        let addr = addr?;

        init();

        let (addrp, len) = addr.into_inner();
        cvt_r(|| unsafe { libc::connect(*self.inner.as_inner(), addrp, len) }).map(drop)
    }

    pub fn connect_timeout(addr: &SocketAddr, timeout: Duration) -> io::Result<TcpStream> {
        init();

        let sock = Socket::new_socket_addr_type(addr, libc::SOCK_STREAM)?;
        sock.connect_timeout(addr, timeout)?;
        Ok(TcpStream { inner: sock })
    }

    pub fn connect_socket_timeout(&self, addr: &SocketAddr, timeout: Duration) -> io::Result<()> {
        self.inner.connect_timeout(addr, timeout)
    }

    pub fn socket(&self) -> &Socket {
        &self.inner
    }

    pub fn into_socket(self) -> Socket {
        self.inner
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_timeout(dur, libc::SO_RCVTIMEO)
    }

    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_timeout(dur, libc::SO_SNDTIMEO)
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.timeout(libc::SO_RCVTIMEO)
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.timeout(libc::SO_SNDTIMEO)
    }

    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.peek(buf)
    }

    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }

    pub fn read_vectored(&self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        self.inner.read_vectored(bufs)
    }

    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let len = cmp::min(buf.len(), <wrlen_t>::max_value() as usize) as wrlen_t;
        let ret = cvt(unsafe {
            libc::send(
                *self.inner.as_inner(),
                buf.as_ptr() as *const c_void,
                len,
                libc::MSG_NOSIGNAL,
            )
        })?;
        Ok(ret as usize)
    }

    pub fn write_vectored(&self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.inner.write_vectored(bufs)
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        sockname(|buf, len| unsafe {
            libc::getpeername(*self.inner.as_inner(), buf, len)
        })
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        sockname(|buf, len| unsafe {
            libc::getsockname(*self.inner.as_inner(), buf, len)
        })
    }

    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }

    pub fn duplicate(&self) -> io::Result<TcpStream> {
        self.inner.duplicate().map(|s| TcpStream { inner: s })
    }

    pub fn set_nodelay(&self, nodelay: bool) -> io::Result<()> {
        self.inner.set_nodelay(nodelay)
    }

    pub fn nodelay(&self) -> io::Result<bool> {
        self.inner.nodelay()
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        setsockopt(&self.inner, libc::IPPROTO_IP, libc::IP_TTL, ttl as c_int)
    }

    pub fn ttl(&self) -> io::Result<u32> {
        let raw: c_int = getsockopt(&self.inner, libc::IPPROTO_IP, libc::IP_TTL)?;
        Ok(raw as u32)
    }

    pub fn set_only_v6(&self, only_v6: bool) -> io::Result<()> {
        setsockopt(&self.inner, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, only_v6 as c_int)
    }

    pub fn only_v6(&self) -> io::Result<bool> {
        let raw: c_int = getsockopt(&self.inner, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY)?;
        Ok(raw != 0)
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }
}

impl FromInner<Socket> for TcpStream {
    fn from_inner(socket: Socket) -> TcpStream {
        TcpStream { inner: socket }
    }
}

impl fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut res = f.debug_struct("TcpStream");

        if let Ok(addr) = self.socket_addr() {
            res.field("addr", &addr);
        }

        if let Ok(peer) = self.peer_addr() {
            res.field("peer", &peer);
        }

        let name = "fd";
        res.field(name, &self.inner.as_inner()).finish()
    }
}

////////////////////////////////////////////////////////////////////////////////
// TCP listeners
////////////////////////////////////////////////////////////////////////////////

pub struct TcpListener {
    inner: Socket,
}

impl TcpListener {
    pub fn new(sockfd: c_int) -> io::Result<TcpListener> {
        let sock = Socket::new(sockfd)?;
        Ok(TcpListener { inner: sock })
    }

    pub fn new_v4() -> io::Result<TcpListener> {
        let sock = Socket::new_raw(libc::AF_INET, libc::SOCK_STREAM)?;
        Ok(TcpListener { inner: sock })
    }

    pub fn new_v6() -> io::Result<TcpListener> {
        let sock = Socket::new_raw(libc::AF_INET6, libc::SOCK_STREAM)?;
        Ok(TcpListener { inner: sock })
    }

    pub fn raw(&self) -> c_int {
        self.inner.raw()
    }

    pub fn into_raw(self) -> c_int {
        self.inner.into_raw()
    }

    pub fn bind(addr: io::Result<&SocketAddr>) -> io::Result<TcpListener> {
        let addr = addr?;

        init();

        let sock = Socket::new_socket_addr_type(addr, libc::SOCK_STREAM)?;

        // On platforms with Berkeley-derived sockets, this allows
        // to quickly rebind a socket, without needing to wait for
        // the OS to clean up the previous one.
        setsockopt(&sock, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1 as c_int)?;

        // Bind our new socket
        let (addrp, len) = addr.into_inner();
        cvt(unsafe { libc::bind(*sock.as_inner(), addrp, len as _) })?;

        // Start listening
        cvt(unsafe { libc::listen(*sock.as_inner(), 128) })?;
        Ok(TcpListener { inner: sock })
    }

    pub fn bind_socket(&self, addr: io::Result<&SocketAddr>) -> io::Result<()> {
        let addr = addr?;

        init();

        setsockopt(&self.inner, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1 as c_int)?;
        let (addrp, len) = addr.into_inner();
        cvt(unsafe { libc::bind(*self.inner.as_inner(), addrp, len as _) })?;
        cvt(unsafe { libc::listen(*self.inner.as_inner(), 128) }).map(drop)
    }

    pub fn socket(&self) -> &Socket {
        &self.inner
    }

    pub fn into_socket(self) -> Socket {
        self.inner
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        sockname(|buf, len| unsafe {
            libc::getsockname(*self.inner.as_inner(), buf, len)
        })
    }

    pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
        let mut len = mem::size_of_val(&storage) as libc::socklen_t;
        let sock = self.inner.accept(&mut storage as *mut _ as *mut _, &mut len)?;
        let addr = sockaddr_to_addr(&storage, len as usize)?;
        Ok((TcpStream { inner: sock }, addr))
    }

    pub fn duplicate(&self) -> io::Result<TcpListener> {
        self.inner.duplicate().map(|s| TcpListener { inner: s })
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        setsockopt(&self.inner, libc::IPPROTO_IP, libc::IP_TTL, ttl as c_int)
    }

    pub fn ttl(&self) -> io::Result<u32> {
        let raw: c_int = getsockopt(&self.inner, libc::IPPROTO_IP, libc::IP_TTL)?;
        Ok(raw as u32)
    }

    pub fn set_only_v6(&self, only_v6: bool) -> io::Result<()> {
        setsockopt(&self.inner, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY, only_v6 as c_int)
    }

    pub fn only_v6(&self) -> io::Result<bool> {
        let raw: c_int = getsockopt(&self.inner, libc::IPPROTO_IPV6, libc::IPV6_V6ONLY)?;
        Ok(raw != 0)
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }
}

impl FromInner<Socket> for TcpListener {
    fn from_inner(socket: Socket) -> TcpListener {
        TcpListener { inner: socket }
    }
}

impl fmt::Debug for TcpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut res = f.debug_struct("TcpListener");

        if let Ok(addr) = self.socket_addr() {
            res.field("addr", &addr);
        }

        let name = "fd";
        res.field(name, &self.inner.as_inner()).finish()
    }
}

////////////////////////////////////////////////////////////////////////////////
// UDP
////////////////////////////////////////////////////////////////////////////////

pub struct UdpSocket {
    inner: Socket,
}

impl UdpSocket {

    pub fn new(sockfd: c_int) -> io::Result<UdpSocket> {
        let sock = Socket::new(sockfd)?;
        Ok(UdpSocket { inner: sock })
    }

    pub fn new_v4() -> io::Result<UdpSocket> {
        let sock = Socket::new_raw(libc::AF_INET, libc::SOCK_DGRAM)?;
        Ok(UdpSocket { inner: sock })
    }

    pub fn new_v6() -> io::Result<UdpSocket> {
        let sock = Socket::new_raw(libc::AF_INET6, libc::SOCK_DGRAM)?;
        Ok(UdpSocket { inner: sock })
    }

    pub fn raw(&self) -> c_int {
        self.inner.raw()
    }

    pub fn into_raw(self) -> c_int {
        self.inner.into_raw()
    }

    pub fn bind(addr: io::Result<&SocketAddr>) -> io::Result<UdpSocket> {
        let addr = addr?;

        init();

        let sock = Socket::new_socket_addr_type(addr, libc::SOCK_DGRAM)?;
        let (addrp, len) = addr.into_inner();
        cvt(unsafe { libc::bind(*sock.as_inner(), addrp, len as _) })?;
        Ok(UdpSocket { inner: sock })
    }

    pub fn bind_socket(&self, addr: io::Result<&SocketAddr>) -> io::Result<()> {
        let addr = addr?;

        init();

        let (addrp, len) = addr.into_inner();
        cvt(unsafe { libc::bind(*self.inner.as_inner(), addrp, len as _) }).map(drop)
    }

    pub fn socket(&self) -> &Socket {
        &self.inner
    }

    pub fn into_socket(self) -> Socket {
        self.inner
    }

    pub fn peer_addr(&self) -> io::Result<SocketAddr> {
        sockname(|buf, len| unsafe {
            libc::getpeername(*self.inner.as_inner(), buf, len)
        })
    }

    pub fn socket_addr(&self) -> io::Result<SocketAddr> {
        sockname(|buf, len| unsafe { 
            libc::getsockname(*self.inner.as_inner(), buf, len) 
        })
    }

    pub fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf)
    }

    pub fn peek_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.peek_from(buf)
    }

    pub fn send_to(&self, buf: &[u8], dst: &SocketAddr) -> io::Result<usize> {
        let len = cmp::min(buf.len(), <wrlen_t>::max_value() as usize) as wrlen_t;
        let (dstp, dstlen) = dst.into_inner();
        let ret = cvt(unsafe {
            libc::sendto(
                *self.inner.as_inner(),
                buf.as_ptr() as *const c_void,
                len,
                libc::MSG_NOSIGNAL,
                dstp,
                dstlen,
            )
        })?;
        Ok(ret as usize)
    }

    pub fn duplicate(&self) -> io::Result<UdpSocket> {
        self.inner.duplicate().map(|s| UdpSocket { inner: s })
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_timeout(dur, libc::SO_RCVTIMEO)
    }

    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_timeout(dur, libc::SO_SNDTIMEO)
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.timeout(libc::SO_RCVTIMEO)
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        self.inner.timeout(libc::SO_SNDTIMEO)
    }

    pub fn set_broadcast(&self, broadcast: bool) -> io::Result<()> {
        setsockopt(&self.inner, libc::SOL_SOCKET, libc::SO_BROADCAST, broadcast as c_int)
    }

    pub fn broadcast(&self) -> io::Result<bool> {
        let raw: c_int = getsockopt(&self.inner, libc::SOL_SOCKET, libc::SO_BROADCAST)?;
        Ok(raw != 0)
    }

    pub fn set_multicast_loop_v4(&self, multicast_loop_v4: bool) -> io::Result<()> {
        setsockopt(&self.inner, libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, multicast_loop_v4 as c_int)
    }

    pub fn multicast_loop_v4(&self) -> io::Result<bool> {
        let raw: c_int = getsockopt(&self.inner, libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP)?;
        Ok(raw != 0)
    }

    pub fn set_multicast_ttl_v4(&self, multicast_ttl_v4: u32) -> io::Result<()> {
        setsockopt(&self.inner, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, multicast_ttl_v4 as c_int)
    }

    pub fn multicast_ttl_v4(&self) -> io::Result<u32> {
        let raw: c_int = getsockopt(&self.inner, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL)?;
        Ok(raw as u32)
    }

    pub fn set_multicast_loop_v6(&self, multicast_loop_v6: bool) -> io::Result<()> {
        setsockopt(&self.inner, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_LOOP, multicast_loop_v6 as c_int)
    }

    pub fn multicast_loop_v6(&self) -> io::Result<bool> {
        let raw: c_int = getsockopt(&self.inner, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_LOOP)?;
        Ok(raw != 0)
    }

    pub fn join_multicast_v4(&self, multiaddr: &Ipv4Addr, interface: &Ipv4Addr) -> io::Result<()> {
        let mreq = libc::ip_mreq {
            imr_multiaddr: *multiaddr.as_inner(),
            imr_interface: *interface.as_inner(),
        };
        setsockopt(&self.inner, libc::IPPROTO_IP, libc::IP_ADD_MEMBERSHIP, mreq)
    }

    pub fn join_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32) -> io::Result<()> {
        let mreq = libc::ipv6_mreq {
            ipv6mr_multiaddr: *multiaddr.as_inner(),
            ipv6mr_interface: to_ipv6mr_interface(interface),
        };
        setsockopt(&self.inner, libc::IPPROTO_IPV6, libc::IPV6_ADD_MEMBERSHIP, mreq)
    }

    pub fn leave_multicast_v4(&self, multiaddr: &Ipv4Addr, interface: &Ipv4Addr) -> io::Result<()> {
        let mreq = libc::ip_mreq {
            imr_multiaddr: *multiaddr.as_inner(),
            imr_interface: *interface.as_inner(),
        };
        setsockopt(&self.inner, libc::IPPROTO_IP, libc::IP_DROP_MEMBERSHIP, mreq)
    }

    pub fn leave_multicast_v6(&self, multiaddr: &Ipv6Addr, interface: u32) -> io::Result<()> {
        let mreq = libc::ipv6_mreq {
            ipv6mr_multiaddr: *multiaddr.as_inner(),
            ipv6mr_interface: to_ipv6mr_interface(interface),
        };
        setsockopt(&self.inner, libc::IPPROTO_IPV6, libc::IPV6_DROP_MEMBERSHIP, mreq)
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        setsockopt(&self.inner, libc::IPPROTO_IP, libc::IP_TTL, ttl as c_int)
    }

    pub fn ttl(&self) -> io::Result<u32> {
        let raw: c_int = getsockopt(&self.inner, libc::IPPROTO_IP, libc::IP_TTL)?;
        Ok(raw as u32)
    }

    pub fn take_error(&self) -> io::Result<Option<io::Error>> {
        self.inner.take_error()
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }

    pub fn peek(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.peek(buf)
    }

    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let len = cmp::min(buf.len(), <wrlen_t>::max_value() as usize) as wrlen_t;
        let ret = cvt(unsafe {
            libc::send(
                *self.inner.as_inner(),
                buf.as_ptr() as *const c_void,
                len,
                libc::MSG_NOSIGNAL,
            )
        })?;
        Ok(ret as usize)
    }

    pub fn connect(&self, addr: io::Result<&SocketAddr>) -> io::Result<()> {
        let (addrp, len) = addr?.into_inner();
        cvt_r(|| unsafe { libc::connect(*self.inner.as_inner(), addrp, len) }).map(drop)
    }
}

impl FromInner<Socket> for UdpSocket {
    fn from_inner(socket: Socket) -> UdpSocket {
        UdpSocket { inner: socket }
    }
}

impl fmt::Debug for UdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut res = f.debug_struct("UdpSocket");

        if let Ok(addr) = self.socket_addr() {
            res.field("addr", &addr);
        }

        let name = "fd";
        res.field(name, &self.inner.as_inner()).finish()
    }
}

mod libc {
    pub use sgx_trts::libc::*;
    pub use sgx_trts::libc::ocall::{bind, listen, connect, setsockopt, getsockopt, send, sendto,
                                    getpeername, getsockname, getaddrinfo, freeaddrinfo};
}