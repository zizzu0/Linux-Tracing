#!/usr/bin/python

# sendmsg   Get a summary of per pid inet conversations (data transmission not packets) 
#           via BPF Compiler Collection (BCC) https://github.com/iovisor/bcc
#           and associate them with dns responses.
#
# OR: Get who is talking to the internet before that communication is closed :)
#
# ONLY FOR IPV4 need to add code for ipv6
# Messages via a kprobe on sock_sendmsg (user space)
# Dns names via uprobes on libc functions
# Organizations via maxminddb databases https://dev.maxmind.com/geoip/geoip2/geolite2/
#
# 15-Feb-2020 Zizzu created this.

from __future__ import print_function
from bcc import BPF
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
from time import strftime
import maxminddb

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/socket.h>
#include <net/sock.h>

struct ipv4_key_t {
    u32 pid;
    u32 daddr;
    u16 dport;
    char proto[5];
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(ipv4_events);

struct hostent {
    char  *h_name;            /* official name of host */
    char **h_aliases;         /* alias list */
    int    h_addrtype;        /* host address type */
    int    h_length;          /* length of address */
    char **h_addr_list;       /* list of addresses */
};

struct addrinfo {
    int              ai_flags;
    int              ai_family;
    int              ai_socktype;
    int              ai_protocol;
    u32              ai_addrlen;
    struct sockaddr *ai_addr;
    char            *ai_canonname;
    struct addrinfo *ai_next;
};

struct val_t {
    u32 pid;
    char host[80];
    struct addrinfo **res;
    struct hostent **result;
};

struct dns_response_t {
    u32 addr;
    char host[80];
};
BPF_PERF_OUTPUT(dns_events);
BPF_HASH(start, u32, struct val_t);

int trace_sock_sendmsg
(struct pt_regs *ctx, struct socket *sock, struct msghdr *msg)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct sockaddr *msg_name = (struct sockaddr *)msg->msg_name;
    if(msg_name) {
        u16 dport = 0, family = msg_name->sa_family;
        
        if (family == AF_INET) {
            struct ipv4_key_t ipv4_key = {.pid = pid};
            bpf_probe_read_str(
                &ipv4_key.proto, sizeof(ipv4_key.proto), sock->sk->__sk_common.skc_prot->name);
            bpf_get_current_comm(&ipv4_key.comm, sizeof(ipv4_key.comm));
            ipv4_key.daddr = ((struct sockaddr_in *)msg_name)->sin_addr.s_addr;
            dport = ((struct sockaddr_in *)msg_name)->sin_port;
            ipv4_key.dport = ntohs(dport);
            ipv4_events.perf_submit(ctx, &ipv4_key, sizeof(ipv4_key));
        }
    }
    else {
        u16 dport = 0, family = sock->sk->__sk_common.skc_family;

        if (family == AF_INET) {
            struct ipv4_key_t ipv4_key = {.pid = pid};
            bpf_probe_read_str(
                &ipv4_key.proto, sizeof(ipv4_key.proto), sock->sk->__sk_common.skc_prot->name);
            ipv4_key.daddr = sock->sk->__sk_common.skc_daddr;
            dport = sock->sk->__sk_common.skc_dport;
            ipv4_key.dport = ntohs(dport);
            bpf_get_current_comm(&ipv4_key.comm, sizeof(ipv4_key.comm));
            ipv4_events.perf_submit(ctx, &ipv4_key, sizeof(ipv4_key));
        }
    }

    return 0;
}

struct hostent *
trace_gethostbyname_entry(struct pt_regs *ctx, const char *name)
{
    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct val_t val = {};
    u32 pid = bpf_get_current_pid_tgid();

    bpf_probe_read(&val.host, sizeof(val.host),
                   (void *)PT_REGS_PARM1(ctx));

    val.pid = bpf_get_current_pid_tgid();
    start.update(&pid, &val);

    return 0;
}

struct hostent *
trace_gethostbyname_return(struct pt_regs *ctx, const char *name)
{
    struct val_t *valp;
    u32 pid = bpf_get_current_pid_tgid();
    struct dns_response_t result = {};

    valp = start.lookup(&pid);
    if (valp == 0)
        return 0;       // missed start

    struct hostent *res = (struct hostent *)PT_REGS_RC(ctx);

    if(res) {
        bpf_probe_read(&result.host, sizeof(result.host), (void *)valp->host);
        result.addr = (u32)res->h_addr_list[0];
        dns_events.perf_submit(ctx, &result, sizeof(result));
    }

    start.delete(&pid);
    return 0;
}

struct hostent *
trace_gethostbyname2_entry(struct pt_regs *ctx, const char *name, int af)
{
    if (!PT_REGS_PARM1(ctx))
        return 0;

    if(af != AF_INET)
        return 0;

    struct val_t val = {};
    u32 pid = bpf_get_current_pid_tgid();

    bpf_probe_read(&val.host, sizeof(val.host),
                   (void *)PT_REGS_PARM1(ctx));

    val.pid = bpf_get_current_pid_tgid();
    start.update(&pid, &val);

    return 0;
}

struct hostent *
trace_gethostbyname2_return(struct pt_regs *ctx, const char *name, int af)
{
    struct val_t *valp;
    u32 pid = bpf_get_current_pid_tgid();
    struct dns_response_t result = {};

    valp = start.lookup(&pid);
    if (valp == 0)
        return 0;       // missed start

    struct hostent *res = (struct hostent *)PT_REGS_RC(ctx);

    if(res) {
        bpf_probe_read(&result.host, sizeof(result.host), (void *)valp->host);
        result.addr = (u32)res->h_addr_list[0];
        dns_events.perf_submit(ctx, &result, sizeof(result));
    }

    start.delete(&pid);
    return 0;
}

int trace_gethostbyname_r_entry
(struct pt_regs *ctx, const char *name, struct hostent *ret,
char *buf, size_t buflen, struct hostent **result, int *h_errnop)
{
    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct val_t val = {};
    u32 pid = bpf_get_current_pid_tgid();

    bpf_probe_read(&val.host, sizeof(val.host),
                   (void *)PT_REGS_PARM1(ctx));


    val.result = result;
    val.pid = bpf_get_current_pid_tgid();
    start.update(&pid, &val);

    return 0;
}

int trace_gethostbyname_r_return
(struct pt_regs *ctx)
{
    struct val_t *valp;
    u32 pid = bpf_get_current_pid_tgid();
    struct dns_response_t result = {};

    valp = start.lookup(&pid);
    if (valp == 0)
        return 0;       // missed start

    struct hostent *res = *valp->result;
    int retval = PT_REGS_RC(ctx);

    if(res && retval == 0) {
        bpf_probe_read(&result.host, sizeof(result.host), (void *)valp->host);
        result.addr = (u32)res->h_addr_list[0];
        dns_events.perf_submit(ctx, &result, sizeof(result));
    }

    start.delete(&pid);
    return 0;
}

int trace_gethostbyname2_r_entry
(struct pt_regs *ctx, const char *name, int af,
struct hostent *ret, char *buf, size_t buflen,
struct hostent **result) // int *h_errnop)
{
    if (!PT_REGS_PARM1(ctx))
        return 0;

    if(af != AF_INET)
        return 0;

    struct val_t val = {};
    u32 pid = bpf_get_current_pid_tgid();

    bpf_probe_read(&val.host, sizeof(val.host),
                   (void *)PT_REGS_PARM1(ctx));

    val.result = result;
    val.pid = bpf_get_current_pid_tgid();
    start.update(&pid, &val);

    return 0;
}

int trace_gethostbyname2_r_return
(struct pt_regs *ctx)
{
    struct val_t *valp;
    u32 pid = bpf_get_current_pid_tgid();
    struct dns_response_t result = {};

    valp = start.lookup(&pid);
    if (valp == 0)
        return 0;       // missed start

    struct hostent *res = *valp->result;
    int retval = PT_REGS_RC(ctx);

    if(res && retval == 0) {
        bpf_probe_read(&result.host, sizeof(result.host), (void *)valp->host);
        result.addr = (u32)res->h_addr_list[0];
        dns_events.perf_submit(ctx, &result, sizeof(result));
    }

    start.delete(&pid);
    return 0;
}

int trace_getaddrinfo_entry
(struct pt_regs *ctx, const char *node, const char *service,
const struct addrinfo *hints, struct addrinfo **res)
{
    if (!PT_REGS_PARM1(ctx))
        return 0;

    struct val_t val = {};
    u32 pid = bpf_get_current_pid_tgid();

    bpf_probe_read(&val.host, sizeof(val.host),
                   (void *)PT_REGS_PARM1(ctx));
    val.res = res;
    val.pid = bpf_get_current_pid_tgid();
    start.update(&pid, &val);

    return 0;
}

int trace_getaddrinfo_return (struct pt_regs *ctx)
{
    struct val_t *valp;
    u32 pid = bpf_get_current_pid_tgid();
    struct dns_response_t result = {};

    valp = start.lookup(&pid);
    if (valp == 0)
        return 0;       // missed start

    struct addrinfo *res = *valp->res;
    int retval = PT_REGS_RC(ctx);

    if(res->ai_family != AF_INET)
        return 0;

    if(res && retval == 0) {
        bpf_probe_read(&result.host, sizeof(result.host), (void *)valp->host);
        result.addr = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
        dns_events.perf_submit(ctx, &result, sizeof(result));
    }

    start.delete(&pid);
    return 0;
}

"""

# load BPF program
b = BPF(text=bpf_text)
if BPF.get_kprobe_functions("sock_sendmsg"):
    b.attach_kprobe(event="sock_sendmsg", fn_name="trace_sock_sendmsg")

#Libraries can be given in the name argument without the lib prefix es: libc -> c
b.attach_uprobe(name="c", sym="gethostbyname", fn_name="trace_gethostbyname_entry")
b.attach_uretprobe(name="c", sym="gethostbyname", fn_name="trace_gethostbyname_return")

b.attach_uprobe(name="c", sym="gethostbyname2", fn_name="trace_gethostbyname2_entry")
b.attach_uretprobe(name="c", sym="gethostbyname2", fn_name="trace_gethostbyname2_return")

b.attach_uprobe(name="c", sym="gethostbyname_r", fn_name="trace_gethostbyname_r_entry")
b.attach_uretprobe(name="c", sym="gethostbyname_r", fn_name="trace_gethostbyname_r_return")

b.attach_uprobe(name="c", sym="gethostbyname2_r", fn_name="trace_gethostbyname2_r_entry")
b.attach_uretprobe(name="c", sym="gethostbyname2_r", fn_name="trace_gethostbyname2_r_return")

b.attach_uprobe(name="c", sym="getaddrinfo", fn_name="trace_getaddrinfo_entry")
b.attach_uretprobe(name="c", sym="getaddrinfo", fn_name="trace_getaddrinfo_return")

dns = {}
conversations = []

def exepath(pid):
    exe = ""
    try:
        with open('/proc/%s/maps' % (pid),'r') as f:
            for line in f:
                try:
                    exe = line[line.index('/'):-1].replace('\n','')
                    break
                except ValueError:
                    continue
        return exe
    except Exception as e:
        return ""

# process events
def print_ipv4_event(cpu, data, size):
    event = b["ipv4_events"].event(data)
    addr = inet_ntop(AF_INET, pack("I", event.daddr))
    host = ""
    if addr in dns:
        host = dns[addr]

    org = None
    with maxminddb.Reader('GeoLite2-ASN.mmdb') as reader:
        res = reader.get(addr)
        if res: org = res['autonomous_system_organization']

    exe = exepath(event.pid)

    if (event.pid, event.proto, addr, event.dport) not in conversations:
        conversations.append((event.pid, event.proto, addr, event.dport))
        print(b"%-9s %-7d %-12.12s %-20.20s %-5s %-16s %-5d %-30s %s" % (
            strftime("%H:%M:%S").encode('ascii'),
            event.pid,
            event.comm,
            exe,
            event.proto,
            addr,
            event.dport,
            org,
            host)
        )

def dns_event(cpu, data, size):
    event = b["dns_events"].event(data)
    addr = inet_ntop(AF_INET, pack("I", event.addr))
    host = event.host.decode('utf-8', 'replace')

    if addr not in dns:
        dns[addr] = host

print("%-9s %-7s %-12.12s %-20.20s %-5s %-16s %-5s %-30s %s" %
    ("SEEN", "PID", "THREAD", "EXE", "PROTO", "REMOTE", "PORT", "ORG", "HOST"))

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["dns_events"].open_perf_buffer(dns_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()




