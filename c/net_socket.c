#include "net_socket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

struct purlin_socket {
    int fd;
    purlin_socket_config_t config;
    bool is_connected;
};

void purlin_socket_config_init(
    purlin_socket_config_t *cfg,
    uint32_t local_ip,
    uint32_t remote_ip,
    uint16_t remote_port
) {
    if (!cfg) return;
    cfg->local_ip = local_ip;
    cfg->local_port = 0; // Dynamic ephemeral port unless explicit
    cfg->remote_ip = remote_ip;
    cfg->remote_port = remote_port ? remote_port : PURLIN_BGP_PORT;
    cfg->send_buf_bytes = 65536; // 64 KB
    cfg->recv_buf_bytes = 65536; // 64 KB
    cfg->non_blocking = true;
    cfg->tcp_nodelay = true;
    cfg->dscp_cs6 = true;
}

static int set_socket_options(int fd, const purlin_socket_config_t *cfg) {
    int opt = 1;
    // 1. SO_REUSEADDR for rapid port rebound
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        return -1;
    }

    // 2. TCP_NODELAY: disable Nagle algorithm to guarantee low-latency routing updates
    if (cfg->tcp_nodelay) {
        int nodelay = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay)) < 0) {
            return -1;
        }
    }

    // 3. DSCP CS6 (IP_TOS 0xC0) for Network Control priority
    if (cfg->dscp_cs6) {
        int tos = PURLIN_DSCP_CS6;
        if (setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) < 0) {
            // Note: some kernel configurations restrict raw TOS modifications; proceed if not fatal
        }
    }

    // 4. Socket buffer tuning
    if (cfg->send_buf_bytes > 0) {
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &cfg->send_buf_bytes, sizeof(cfg->send_buf_bytes));
    }
    if (cfg->recv_buf_bytes > 0) {
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &cfg->recv_buf_bytes, sizeof(cfg->recv_buf_bytes));
    }

    // 5. Non-blocking mode configuration via fcntl
    if (cfg->non_blocking) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            return -1;
        }
    }

    return 0;
}

purlin_sock_result_t purlin_socket_connect(
    const purlin_socket_config_t *cfg,
    purlin_socket_t **sock_out
) {
    if (!cfg || !sock_out) return PURLIN_SOCK_ERR_SOCKET;

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        return PURLIN_SOCK_ERR_SOCKET;
    }

    if (set_socket_options(fd, cfg) < 0) {
        close(fd);
        return PURLIN_SOCK_ERR_SETSOCKOPT;
    }

    // Bind to local address if requested
    if (cfg->local_ip != 0 || cfg->local_port != 0) {
        struct sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(local_addr));
        local_addr.sin_family = AF_INET;
        local_addr.sin_addr.s_addr = htonl(cfg->local_ip);
        local_addr.sin_port = htons(cfg->local_port);

        if (bind(fd, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
            close(fd);
            return PURLIN_SOCK_ERR_BIND;
        }
    }

    // Prepare remote endpoint address
    struct sockaddr_in remote_addr;
    memset(&remote_addr, 0, sizeof(remote_addr));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = htonl(cfg->remote_ip);
    remote_addr.sin_port = htons(cfg->remote_port);

    int rc = connect(fd, (struct sockaddr *)&remote_addr, sizeof(remote_addr));
    bool is_connected = (rc == 0);

    if (rc < 0 && errno != EINPROGRESS && errno != EWOULDBLOCK) {
        close(fd);
        return PURLIN_SOCK_ERR_CONNECT;
    }

    purlin_socket_t *sock = (purlin_socket_t *)malloc(sizeof(purlin_socket_t));
    if (!sock) {
        close(fd);
        return PURLIN_SOCK_ERR_SOCKET;
    }

    sock->fd = fd;
    sock->config = *cfg;
    sock->is_connected = is_connected;
    *sock_out = sock;

    return (rc == 0) ? PURLIN_SOCK_OK : PURLIN_SOCK_WOULDBLOCK;
}

purlin_sock_result_t purlin_socket_listen(
    uint32_t bind_ip,
    uint16_t bind_port,
    purlin_socket_t **server_sock_out
) {
    if (!server_sock_out) return PURLIN_SOCK_ERR_SOCKET;

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) return PURLIN_SOCK_ERR_SOCKET;

    purlin_socket_config_t cfg;
    purlin_socket_config_init(&cfg, bind_ip, 0, 0);
    cfg.local_port = bind_port ? bind_port : PURLIN_BGP_PORT;

    if (set_socket_options(fd, &cfg) < 0) {
        close(fd);
        return PURLIN_SOCK_ERR_SETSOCKOPT;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(bind_ip);
    addr.sin_port = htons(cfg.local_port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return PURLIN_SOCK_ERR_BIND;
    }

    if (listen(fd, 64) < 0) {
        close(fd);
        return PURLIN_SOCK_ERR_SOCKET;
    }

    purlin_socket_t *sock = (purlin_socket_t *)malloc(sizeof(purlin_socket_t));
    if (!sock) {
        close(fd);
        return PURLIN_SOCK_ERR_SOCKET;
    }

    sock->fd = fd;
    sock->config = cfg;
    sock->is_connected = false;
    *server_sock_out = sock;

    return PURLIN_SOCK_OK;
}

purlin_sock_result_t purlin_socket_accept(
    purlin_socket_t *server_sock,
    purlin_socket_t **client_sock_out,
    uint32_t *peer_ip_out,
    uint16_t *peer_port_out
) {
    if (!server_sock || !client_sock_out) return PURLIN_SOCK_ERR_SOCKET;

    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    memset(&client_addr, 0, sizeof(client_addr));

    int client_fd = accept(server_sock->fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return PURLIN_SOCK_WOULDBLOCK;
        }
        return PURLIN_SOCK_ERR_IO;
    }

    purlin_socket_config_t cfg;
    purlin_socket_config_init(&cfg, 0, ntohl(client_addr.sin_addr.s_addr), ntohs(client_addr.sin_port));

    if (set_socket_options(client_fd, &cfg) < 0) {
        close(client_fd);
        return PURLIN_SOCK_ERR_SETSOCKOPT;
    }

    purlin_socket_t *client_sock = (purlin_socket_t *)malloc(sizeof(purlin_socket_t));
    if (!client_sock) {
        close(client_fd);
        return PURLIN_SOCK_ERR_SOCKET;
    }

    client_sock->fd = client_fd;
    client_sock->config = cfg;
    client_sock->is_connected = true;

    if (peer_ip_out) *peer_ip_out = ntohl(client_addr.sin_addr.s_addr);
    if (peer_port_out) *peer_port_out = ntohs(client_addr.sin_port);

    *client_sock_out = client_sock;
    return PURLIN_SOCK_OK;
}

purlin_sock_result_t purlin_socket_send(
    purlin_socket_t *sock,
    const uint8_t *buf,
    size_t len,
    size_t *bytes_sent
) {
    if (!sock || !buf) return PURLIN_SOCK_ERR_IO;
    if (bytes_sent) *bytes_sent = 0;

    ssize_t n = send(sock->fd, buf, len, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return PURLIN_SOCK_WOULDBLOCK;
        }
        return PURLIN_SOCK_ERR_IO;
    }

    if (bytes_sent) *bytes_sent = (size_t)n;
    return PURLIN_SOCK_OK;
}

purlin_sock_result_t purlin_socket_recv(
    purlin_socket_t *sock,
    uint8_t *buf,
    size_t max_len,
    size_t *bytes_read
) {
    if (!sock || !buf) return PURLIN_SOCK_ERR_IO;
    if (bytes_read) *bytes_read = 0;

    ssize_t n = recv(sock->fd, buf, max_len, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return PURLIN_SOCK_WOULDBLOCK;
        }
        return PURLIN_SOCK_ERR_IO;
    }
    if (n == 0) {
        // Orderly peer shutdown
        return PURLIN_SOCK_CLOSED;
    }

    if (bytes_read) *bytes_read = (size_t)n;
    return PURLIN_SOCK_OK;
}

void purlin_socket_close(purlin_socket_t *sock) {
    if (!sock) return;
    if (sock->fd >= 0) {
        close(sock->fd);
        sock->fd = -1;
    }
    free(sock);
}

int purlin_socket_get_fd(const purlin_socket_t *sock) {
    return sock ? sock->fd : -1;
}
