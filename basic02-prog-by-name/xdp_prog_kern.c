/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Notice how this XDP/BPF-program contains several programs in the same source
 * file. These will each get their own section in the ELF file, and via libbpf
 * they can be selected individually, and via their file-descriptor attached to
 * a given kernel BPF-hook.
 * 这个程序包含多个XDP程序,但是只有一个源文件
 * 在elf文件内部他们有自己的 .text section 可以通过libbpf被单独加载
 *
 * The libbpf bpf_object__find_program_by_title() refers to SEC names below.
 * The iproute2 utility also use section name.
 *
 * Slightly confusing, the names that gets listed by "bpftool prog" are the
 * C-function names (below the SEC define).
 */

SEC("xdp")
int  xdp_pass_func(struct xdp_md *ctx)
{
	return XDP_PASS;
}

SEC("xdp")
int  xdp_drop_func(struct xdp_md *ctx)
{
	return XDP_DROP;
}

/* Assignment#2: Add new XDP program section that use XDP_ABORTED */
// XDP_ABORTED 和 XDP_DROP 是不同的。因为 XDP_ABORTED 会触发一个名为 xdp:xdp_exception 的 tracepoint（追踪点）。
// 这里是一个利用tracepoint进行调试的方法 + perf 探针
SEC("xdp")
int	xdp_abort_func(struct xdp_md *ctx)
{
	return XDP_ABORTED;
}

char _license[] SEC("license") = "GPL";

/* Hint the avail XDP action return codes are:

enum xdp_action {
	XDP_ABORTED = 0,
	XDP_DROP,
	XDP_PASS,
	XDP_TX,
	XDP_REDIRECT,
};
*/
