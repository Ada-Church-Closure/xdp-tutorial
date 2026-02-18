/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// 这是在内核中运行的文件
SEC("xdp")
int  xdp_prog_simple(struct xdp_md *ctx)
{
	// 执行的verdict
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
