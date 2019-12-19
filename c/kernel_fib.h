#ifndef PURLIN_KERNEL_FIB_H
#define PURLIN_KERNEL_FIB_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Maximum multipath next-hops per route entry
#define PURLIN_MAX_NEXTHOPS 16

// Next-hop descriptor for kernel route installation
typedef struct {
    uint32_t gateway_ip;   // Host byte order IPv4 address
    uint32_t if_index;     // Egress interface index (0 if unspecified)
    uint8_t weight;        // ECMP path weight
} purlin_nexthop_t;

// Route operation status codes
typedef enum {
    PURLIN_FIB_OK = 0,
    PURLIN_FIB_ERR_SOCKET = -1,
    PURLIN_FIB_ERR_INSTALL = -2,
    PURLIN_FIB_ERR_DELETE = -3,
    PURLIN_FIB_ERR_NOT_SUPPORTED = -4
} purlin_fib_result_t;

// Opaque kernel FIB controller handle
typedef struct purlin_kernel_fib purlin_kernel_fib_t;

// Open kernel routing table controller (Netlink on Linux, AF_ROUTE on BSD/macOS)
purlin_fib_result_t purlin_kernel_fib_open(purlin_kernel_fib_t **fib_out);

// Install or update a route entry into the kernel FIB
purlin_fib_result_t purlin_kernel_fib_install(
    purlin_kernel_fib_t *fib,
    uint32_t dest_ip,
    uint8_t prefix_len,
    const purlin_nexthop_t *nexthops,
    size_t nexthop_count
);

// Delete a route entry from the kernel FIB
purlin_fib_result_t purlin_kernel_fib_delete(
    purlin_kernel_fib_t *fib,
    uint32_t dest_ip,
    uint8_t prefix_len
);

// Close kernel routing table controller and free resources
void purlin_kernel_fib_close(purlin_kernel_fib_t *fib);

#ifdef __cplusplus
}
#endif

#endif // PURLIN_KERNEL_FIB_H
