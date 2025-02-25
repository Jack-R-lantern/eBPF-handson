#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "frag_detect.h"

char *ifname = NULL;

void cleanup_tc() {
	fprintf(stderr, "Cleaning up tc qdisc and filters...\n");

	// tc filter 삭제
	char del_filter_cmd[128];
	snprintf(del_filter_cmd, sizeof(del_filter_cmd), "tc filter del dev %s ingress", ifname);
	system(del_filter_cmd);

	// tc qdisc 삭제
	char del_qdisc_cmd[128];
	snprintf(del_qdisc_cmd, sizeof(del_qdisc_cmd), "tc qdisc del dev %s clsact", ifname);
	system(del_qdisc_cmd);

	printf("Cleanup complete.\n");
}

void signal_handler(int signum) {
	printf("\nRecevied signal %d, exiting...\n", signum);
	cleanup_tc();
	exit(0);
}

void setup_signals() {
	struct sigaction	sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = signal_handler;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
}

int	main(int argc, char **argv) {
	int opt;

	struct option long_option[] = {
		{"ifname", required_argument, 0, 'i'},
		{0, 0, 0, 0}
	};

	while ((opt = getopt_long(argc, argv, "i:", long_option, NULL)) != -1) {
		switch (opt) {
		case 'i':
			ifname = optarg;
			break;
		case '?':
			fprintf(stderr, "Usage: %s --ifname <interface>\n", argv[0]);
			return EXIT_FAILURE;
		}
	}
	
	struct frag_detect *skel;
	int prog_fd, err;
	char cmd[128];




	// BPF 프로그램 로드
	skel = frag_detect__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load BPF program\n");
		return 1;
	}

	// eBPF 프로그램이 파일 디스크립터 가져오기
	prog_fd = bpf_program__fd(skel->progs.frag_detect);
	if (prog_fd < 0) {
		fprintf(stderr, "Failed to get program FD\n");
		return 1;
	}

	// `tc` 명령어를 사용하여 프로그래을 ingress에 attach
	snprintf(cmd, sizeof(cmd), "tc qdisc add dev %s clsact", ifname);
	system(cmd);
	snprintf(cmd, sizeof(cmd), "tc filter add dev %s ingress bpf direct-action obj frag_detect.o sec classifier", ifname);
	system(cmd);

	setup_signals();

	while (1)
	{
	}
	
	return 0;
}