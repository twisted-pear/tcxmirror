#include <assert.h>
#include <bpf/bpf.h>
#include <limits.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "tcxmirror_kern.skel.h"

#define PROGS_MAX 512

enum tcxmirror_error_codes {
	TCXMIRROR_ERR_OK = 0,
	TCXMIRROR_ERR_USAGE,
	TCXMIRROR_ERR_BPF,
	TCXMIRROR_ERR_IFINDEX,
	TCXMIRROR_ERR_SAMEIF,
	TCXMIRROR_ERR_SIG_HANDLER,
	TCXMIRROR_ERR_MAX
};

static struct tcxmirror_kern *bpf_kern = NULL;
static struct bpf_link *link_ingress = NULL;
static struct bpf_link *link_egress = NULL;

static volatile sig_atomic_t keep_going = true;

static void signal_handler(int signal)
{
	switch (signal) {
		case SIGINT:
		case SIGQUIT:
		case SIGTERM:
			keep_going = false;
			break;
		default:
			assert(0);
	}
}

static _Noreturn void cleanup_and_exit(enum tcxmirror_error_codes exit_code)
{
	if (link_ingress != NULL) {
		bpf_link__detach(link_ingress);
		bpf_link__destroy(link_ingress);
	}

	if (link_egress != NULL) {
		bpf_link__detach(link_egress);
		bpf_link__destroy(link_egress);
	}

	if (bpf_kern != NULL) {
		tcxmirror_kern__destroy(bpf_kern);
	}

	exit(exit_code);
}

static struct bpf_link *attach_at_idx(__u32 ifidx, __u32 prog_idx, enum
		bpf_attach_type type)
{
	__u32 prog_ids[PROGS_MAX];
	__u32 prog_cnt = PROGS_MAX;
	__u32 attach_flags = 0;

	int err = bpf_prog_query(ifidx, type, 0, &attach_flags,
			prog_ids, &prog_cnt);
	if (err != 0) {
		errno = -err;
		return NULL;
	}

	struct bpf_program *prog = bpf_kern->progs.tcxmirror_out;
	if (type == BPF_TCX_INGRESS) {
		prog = bpf_kern->progs.tcxmirror_in;
	}

	LIBBPF_OPTS(bpf_tcx_opts, insert_opts);

	/* only program */
	if (prog_cnt == 0) {
		insert_opts.flags = 0;
	/* insert last */
	} else if (prog_idx >= prog_cnt) {
		insert_opts.flags = BPF_F_AFTER;
		insert_opts.relative_id = prog_ids[prog_cnt - 1];
	/* insert before */
	} else {
		insert_opts.flags = BPF_F_BEFORE;
		insert_opts.relative_id = prog_ids[prog_idx];
	}

	return bpf_program__attach_tcx(prog, ifidx, &insert_opts);
}

static _Noreturn void usage() {
	printf("Usage: tcxmirror -i <first|last> -e <first|last> <attach if> <mirror if>\n");
	exit(TCXMIRROR_ERR_USAGE);
}

static __u32 get_prog_idx(const char *arg)
{
	if (strcmp("first", arg) == 0) {
		return 0;
	}

	if (strcmp("last", arg) == 0) {
		return UINT32_MAX;
	}

	return strtoul(arg, NULL, 0);
}

int main(int argc, char **argv)
{
	int ingress_prog_idx = UINT32_MAX;
	int egress_prog_idx = 0;

	int opt;
	while ((opt = getopt(argc, argv, "i:e:")) != -1) {
		switch (opt) {
			case 'i':
				ingress_prog_idx = get_prog_idx(optarg);
				break;
			case 'e':
				egress_prog_idx = get_prog_idx(optarg);
				break;
			default:
				usage();
		}
	}

	if (optind + 1 >= argc) {
		usage();
	}

	char *attach_ifname = argv[optind];
	__u32 attach_if_idx = if_nametoindex(attach_ifname);
	if (attach_if_idx == 0) {
		perror("attach ifindex");
		cleanup_and_exit(TCXMIRROR_ERR_IFINDEX);
	}

	char *mirror_ifname = argv[optind + 1];
	__u32 mirror_if_idx = if_nametoindex(mirror_ifname);
	if (mirror_if_idx == 0) {
		perror("mirror ifindex");
		cleanup_and_exit(TCXMIRROR_ERR_IFINDEX);
	}

	if (attach_if_idx == mirror_if_idx) {
		fprintf(stderr, "cannot mirror to same interface\n");
		cleanup_and_exit(TCXMIRROR_ERR_SAMEIF);
	}

	bpf_kern = tcxmirror_kern__open_and_load();
	if (bpf_kern == NULL) {
		perror("load BPF kernel objects");
		cleanup_and_exit(TCXMIRROR_ERR_BPF);
	}

	__u32 key = 0;
	int err = bpf_map__update_elem(bpf_kern->maps.tcxmirror_if,
			&key, sizeof(__u32), &mirror_if_idx, sizeof(__u32),
			BPF_ANY);
	if (err != 0) {
		errno = -err;
		perror("update IF config BPF map");
		cleanup_and_exit(TCXMIRROR_ERR_BPF);
	}

	link_ingress = attach_at_idx(attach_if_idx, ingress_prog_idx,
			BPF_TCX_INGRESS);
	if (link_ingress == NULL) {
		perror("attaching ingress BPF program");
		cleanup_and_exit(TCXMIRROR_ERR_BPF);
	}
	link_egress = attach_at_idx(attach_if_idx, egress_prog_idx,
			BPF_TCX_EGRESS);
	if (link_egress == NULL) {
		perror("attaching egress BPF program");
		cleanup_and_exit(TCXMIRROR_ERR_BPF);
	}

	struct sigaction sig_act;
	memset(&sig_act, 0, sizeof(sig_act));
	sig_act.sa_handler = signal_handler;
	if (sigaction(SIGINT, &sig_act, NULL) < 0
			|| sigaction(SIGQUIT, &sig_act, NULL) < 0
			|| sigaction(SIGTERM, &sig_act, NULL) < 0) {
		perror("setting signal handler");
		cleanup_and_exit(TCXMIRROR_ERR_SIG_HANDLER);
	}

	while (keep_going) {
		sleep(1);
	}

	cleanup_and_exit(TCXMIRROR_ERR_OK);
}
