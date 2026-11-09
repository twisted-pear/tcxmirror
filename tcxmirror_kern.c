/* SPDX-License-Identifier: GPL-2.0 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
} tcxmirror_if SEC(".maps");

static __always_inline void mirror_to_if(struct __sk_buff *ctx)
{
	__u32 key = 0;
	__u32 *mirror_if = bpf_map_lookup_elem(&tcxmirror_if, &key);
	if (mirror_if == NULL) {
		return;
	}

	bpf_clone_redirect(ctx, *mirror_if, 0);
}

SEC("tcx/ingress")
int tcxmirror_in(struct __sk_buff *ctx)
{
	mirror_to_if(ctx);
	return TCX_NEXT;
}

SEC("tcx/egress")
int tcxmirror_out(struct __sk_buff *ctx)
{
	mirror_to_if(ctx);
	return TCX_NEXT;
}

char _license[] SEC("license") = "GPL";
