## Sockets

### socket

`socket(domain, type, protocol) → fd`

**Success**: Returns fd.
- `SOCK_STREAM` → reliable, connection-based (TCP)
- `SOCK_DGRAM` → unreliable, connectionless (UDP)
- `SOCK_RAW` → raw protocol access
- `SOCK_CLOEXEC` → sets `O_CLOEXEC`
- `SOCK_NONBLOCK` → sets `O_NONBLOCK`

**Errors**:
- `EACCES` — permission denied (e.g. `SOCK_RAW` without `CAP_NET_RAW`)
- `EAFNOSUPPORT` — address family not supported
- `EINVAL` — unknown protocol; or invalid flags
- `EMFILE` — process fd limit
- `ENFILE` — system fd limit
- `ENOBUFS` / `ENOMEM` — insufficient memory
- `EPROTONOSUPPORT` — protocol not supported within given family/type

### socketpair

`socketpair(domain, type, protocol, sv[2]) → 0`

**Success**: Returns 0. Creates two connected sockets in `sv[0]` and `sv[1]`. Each can read what the other writes.

**Errors**:
- `EAFNOSUPPORT` — address family not supported for socketpair
- `EFAULT` — bad `sv` pointer
- `EMFILE` — process fd limit
- `ENFILE` — system fd limit
- `ENOMEM` — insufficient memory
- `EOPNOTSUPP` — protocol doesn't support socketpair
- `EPROTONOSUPPORT` — protocol not supported

### bind

`bind(sockfd, addr, addrlen) → 0`

**Success**: Returns 0. Assigns address to socket.

**Errors**:
- `EACCES` — address is protected (e.g. binding to port < 1024 without `CAP_NET_BIND_SERVICE`); or path permission denied (Unix domain)
- `EADDRINUSE` — address already in use; or all ephemeral ports used
- `EADDRNOTAVAIL` — requested address not available on this machine
- `EBADF` — fd not valid
- `EFAULT` — bad `addr` pointer
- `EINVAL` — socket already bound; or `addrlen` wrong; or invalid address
- `ELOOP` — too many symlinks (Unix domain)
- `ENAMETOOLONG` — path too long (Unix domain)
- `ENOENT` — path prefix doesn't exist (Unix domain)
- `ENOMEM` — insufficient memory
- `ENOTDIR` — path component not directory (Unix domain)
- `ENOTSOCK` — fd not a socket
- `EROFS` — read-only filesystem (Unix domain)

### listen

`listen(sockfd, backlog) → 0`

**Success**: Returns 0. Marks socket as passive. `backlog` limits pending connection queue.

**Errors**:
- `EADDRINUSE` — another socket already listening on same address
- `EBADF` — fd not valid
- `ENOTSOCK` — fd not a socket
- `EOPNOTSUPP` — socket type doesn't support listen (e.g. `SOCK_DGRAM`)

### accept / accept4

`accept(sockfd, addr, addrlen) → fd`
`accept4(sockfd, addr, addrlen, flags) → fd`

**Success**: Returns new connected fd. If `addr` not NULL, filled with peer address. `accept4` accepts `SOCK_CLOEXEC` and `SOCK_NONBLOCK` flags.

**Errors**:
- `EAGAIN` / `EWOULDBLOCK` — socket is non-blocking and no connections pending
- `EBADF` — fd not valid
- `ECONNABORTED` — connection aborted by peer before accept completed
- `EFAULT` — bad `addr` pointer
- `EINTR` — interrupted by signal
- `EINVAL` — socket not listening; or `accept4` invalid flags; or `addrlen` invalid
- `EMFILE` — process fd limit
- `ENFILE` — system fd limit
- `ENOBUFS` / `ENOMEM` — insufficient memory
- `ENOTSOCK` — fd not a socket
- `EOPNOTSUPP` — socket type not `SOCK_STREAM`
- `EPERM` — firewall rules block connection
- `EPROTO` — protocol error

### connect

`connect(sockfd, addr, addrlen) → 0`

**Success**: Returns 0. For `SOCK_STREAM`: establishes TCP connection. For `SOCK_DGRAM`: sets default destination.

**Errors**:
- `EACCES` — broadcast without `SO_BROADCAST`; or Unix socket permission denied; or SELinux denial
- `EADDRINUSE` — local address already in use
- `EADDRNOTAVAIL` — no free local port; or address not available
- `EAFNOSUPPORT` — address family mismatch
- `EAGAIN` — no free local port in ephemeral range; or routing cache insufficient
- `EALREADY` — non-blocking socket and previous connect not completed
- `EBADF` — fd not valid
- `ECONNREFUSED` — remote host actively refused connection (RST)
- `EFAULT` — bad `addr` pointer
- `EINPROGRESS` — non-blocking socket and connection cannot complete immediately (use `poll`/`epoll` for completion)
- `EINTR` — interrupted by signal; connection may proceed in background
- `EINVAL` — invalid argument; or `connect` on listening socket (some implementations)
- `EISCONN` — socket already connected
- `ENETUNREACH` — no route to network
- `ENOTSOCK` — fd not a socket
- `EPROTOTYPE` — socket type mismatch with address type
- `ETIMEDOUT` — connection timed out (no response from peer)

### send / sendto / sendmsg / sendmmsg

`send(sockfd, buf, len, flags) → bytes_sent`
`sendto(sockfd, buf, len, flags, dest_addr, addrlen) → bytes_sent`
`sendmsg(sockfd, msg, flags) → bytes_sent`
`sendmmsg(sockfd, msgvec, vlen, flags) → messages_sent`

**Success**: Returns bytes sent (`send`/`sendto`/`sendmsg`); or number of messages sent (`sendmmsg`).
- `send` on connected socket; `sendto` with or without address; `sendmsg` with `msghdr` (scatter-gather + ancillary data); `sendmmsg` batches multiple messages
- `MSG_NOSIGNAL` → suppress `SIGPIPE`
- `MSG_DONTWAIT` → non-blocking this call only
- `MSG_MORE` → more data coming (cork)
- `MSG_OOB` → send out-of-band data

**Errors**:
- `EACCES` — broadcast without `SO_BROADCAST`; or permission denied
- `EAGAIN` / `EWOULDBLOCK` — non-blocking and buffer full
- `EALREADY` — non-blocking and previous operation not complete
- `EBADF` — fd not valid
- `ECONNREFUSED` — peer not listening (UDP); or connection-based error received
- `ECONNRESET` — connection reset by peer
- `EDESTADDRREQ` — socket not connected and no address given (`sendto`)
- `EFAULT` — bad buffer or address pointer
- `EINTR` — interrupted by signal
- `EINVAL` — invalid argument
- `EISCONN` — `sendto`/`sendmsg` with address on already-connected socket
- `EMSGSIZE` — message too large to send atomically (e.g. UDP packet > MTU with `IP_DONTFRAG`)
- `ENOBUFS` — output queue full (transient)
- `ENOMEM` — insufficient memory
- `ENOTCONN` — socket not connected (stream socket)
- `ENOTSOCK` — fd not a socket
- `EOPNOTSUPP` — flags not supported
- `EPIPE` — connection shut down for writing; `SIGPIPE` delivered unless `MSG_NOSIGNAL`

### recv / recvfrom / recvmsg / recvmmsg

`recv(sockfd, buf, len, flags) → bytes_received`
`recvfrom(sockfd, buf, len, flags, src_addr, addrlen) → bytes_received`
`recvmsg(sockfd, msg, flags) → bytes_received`
`recvmmsg(sockfd, msgvec, vlen, flags, timeout) → messages_received`

**Success**: Returns bytes received (0 = peer shutdown orderly). `recvfrom` fills sender address. `recvmsg` fills `msghdr` including ancillary data. `recvmmsg` returns message count.
- `MSG_PEEK` → receive without consuming
- `MSG_WAITALL` → block until full `len` received
- `MSG_DONTWAIT` → non-blocking this call only
- `MSG_OOB` → receive out-of-band data
- `MSG_TRUNC` → (with `MSG_PEEK`) return real packet length even if buffer smaller

**Errors**:
- `EAGAIN` / `EWOULDBLOCK` — non-blocking and no data available
- `EBADF` — fd not valid
- `ECONNREFUSED` — UDP peer unreachable (ICMP error cached)
- `ECONNRESET` — connection reset by peer
- `EFAULT` — bad buffer or address pointer
- `EINTR` — interrupted by signal
- `EINVAL` — invalid argument
- `ENOTCONN` — stream socket not connected
- `ENOTSOCK` — fd not a socket
- `ENOMEM` — insufficient memory

### setsockopt

`setsockopt(sockfd, level, optname, optval, optlen) → 0`

**Success**: Returns 0. Sets option at given level.
- Common: `SO_REUSEADDR`, `SO_REUSEPORT`, `SO_KEEPALIVE`, `SO_LINGER`, `SO_RCVBUF`, `SO_SNDBUF`, `SO_RCVTIMEO`, `SO_SNDTIMEO`, `TCP_NODELAY`

**Errors**:
- `EBADF` — fd not valid
- `EFAULT` — bad `optval` pointer
- `EINVAL` — `optlen` invalid; or value invalid for the option
- `ENOPROTOOPT` — unknown option at given level
- `ENOTSOCK` — fd not a socket

### getsockopt

`getsockopt(sockfd, level, optname, optval, optlen) → 0`

**Success**: Returns 0. Fills `optval` with current option value.

**Errors**: Same as `setsockopt`.

### getsockname

`getsockname(sockfd, addr, addrlen) → 0`

**Success**: Returns 0. Fills `addr` with local address of socket.

**Errors**:
- `EBADF` — fd not valid
- `EFAULT` — bad pointer
- `EINVAL` — `addrlen` invalid
- `ENOBUFS` — insufficient resources
- `ENOTSOCK` — fd not a socket

### getpeername

`getpeername(sockfd, addr, addrlen) → 0`

**Success**: Returns 0. Fills `addr` with peer address.

**Errors**:
- `EBADF` — fd not valid
- `EFAULT` — bad pointer
- `EINVAL` — `addrlen` invalid
- `ENOBUFS` — insufficient resources
- `ENOTCONN` — socket not connected
- `ENOTSOCK` — fd not a socket

### pause

`pause() → (returns -1 with EINTR after signal)`

**Success**: Does not return on success. Suspends process until a signal is delivered that either terminates the process or invokes a handler.

**Errors**:
- `EINTR` — signal caught and handler returned (this is the only way `pause` returns)

### shutdown

`shutdown(sockfd, how) → 0`

**Success**: Returns 0.
- `SHUT_RD` → no more receives; further reads return 0
- `SHUT_WR` → no more sends; FIN sent for TCP; further writes → `EPIPE`
- `SHUT_RDWR` → both

**Errors**:
- `EBADF` — fd not valid
- `EINVAL` — invalid `how`
- `ENOTCONN` — socket not connected (stream)
- `ENOTSOCK` — fd not a socket
