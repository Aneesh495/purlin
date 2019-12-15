#ifndef PURLIN_NET_SOCKET_H
#define PURLIN_NET_SOCKET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Standard BGP default TCP port (RFC 4271)
#define PURLIN_BGP_PORT 179

// Differentiated Services Code Point (DSCP) CS6: Class Selector 6 (0xC0 = 192)
// Network Control priority for BGP routing protocol traffic (RFC 2474 / RFC 4271)
#define PURLIN_DSCP_CS6 0xC0

// Socket configuration options
typedef struct {
    uint32_t local_ip;        // Host byte order IPv4 address
    uint16_t local_port;      // Local binding port (default 179)
    uint32_t remote_ip;       // Peer IPv4 address
    uint16_t remote_port;     // Peer BGP port (default 179)
    int send_buf_bytes;       // TCP send buffer size (e.g. 64KB)
    int recv_buf_bytes;       // TCP receive buffer size (e.g. 64KB)
    bool non_blocking;        // Configure O_NONBLOCK
    bool tcp_nodelay;         // Disable Nagle algorithm
    bool dscp_cs6;            // Set IP_TOS to CS6 (Network Control)
} purlin_socket_config_t;

// Opaque socket handle
typedef struct purlin_socket purlin_socket_t;

// Connection status codes
typedef enum {
    PURLIN_SOCK_OK = 0,
    PURLIN_SOCK_WOULDBLOCK = 1,
    PURLIN_SOCK_CLOSED = 2,
    PURLIN_SOCK_ERR_SOCKET = -1,
    PURLIN_SOCK_ERR_BIND = -2,
    PURLIN_SOCK_ERR_CONNECT = -3,
    PURLIN_SOCK_ERR_SETSOCKOPT = -4,
    PURLIN_SOCK_ERR_IO = -5
} purlin_sock_result_t;

// Initialize default socket configuration for BGP peering
void purlin_socket_config_init(
    purlin_socket_config_t *cfg,
    uint32_t local_ip,
    uint32_t remote_ip,
    uint16_t remote_port
);

// Create and configure a non-blocking TCP socket for active peering
purlin_sock_result_t purlin_socket_connect(
    const purlin_socket_config_t *cfg,
    purlin_socket_t **sock_out
);

// Create a listening server socket on local BGP port
purlin_sock_result_t purlin_socket_listen(
    uint32_t bind_ip,
    uint16_t bind_port,
    purlin_socket_t **server_sock_out
);

// Accept incoming peer connection from listening socket
purlin_sock_result_t purlin_socket_accept(
    purlin_socket_t *server_sock,
    purlin_socket_t **client_sock_out,
    uint32_t *peer_ip_out,
    uint16_t *peer_port_out
);

// Send wire bytes non-blockingly over socket
// Returns number of bytes sent, or negative on error, or PURLIN_SOCK_WOULDBLOCK
purlin_sock_result_t purlin_socket_send(
    purlin_socket_t *sock,
    const uint8_t *buf,
    size_t len,
    size_t *bytes_sent
);

// Receive wire bytes non-blockingly into destination buffer
purlin_sock_result_t purlin_socket_recv(
    purlin_socket_t *sock,
    uint8_t *buf,
    size_t max_len,
    size_t *bytes_read
);

// Close socket and release allocated resources
void purlin_socket_close(purlin_socket_t *sock);

// Retrieve underlying OS file descriptor
int purlin_socket_get_fd(const purlin_socket_t *sock);

#ifdef __cplusplus
}
#endif

#endif // PURLIN_NET_SOCKET_H
