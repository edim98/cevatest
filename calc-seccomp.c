#include <stdio.h>
#include <seccomp.h>

int setup_seccomp() {
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_KILL);
	int calls[] = { SCMP_SYS(read), SCMP_SYS(write), SCMP_SYS(exit_group), SCMP_SYS(fstat), SCMP_SYS(mmap), SCMP_SYS(lseek) };
	int calls_length = sizeof(calls)/sizeof(calls[0]);
	int i;
	if (ctx == NULL) {
		return -1;
	}
	for (i = 0; i < calls_length; i++) {
		if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, calls[i], 0) < 0) {
			seccomp_release(ctx);
			fprintf(stderr, "adding rule %d failed\n", i);
			return -1;
		}
	}
	if (seccomp_load(ctx) < 0) {
		seccomp_release(ctx);
		fprintf(stderr, "loading seccomp failed\n");
		return -1;
	}
	return 0;
}

void calcloop() {
	int a,b;
	int matched;
	while(1) {
		matched = scanf("%d %d", &a, &b);
		if(matched != 2) {
			printf("Bye!\n");
			return;
		}
		printf("%d + %d = %d\n", a, b, a+b);
	}
}

int main(int argc, char ** argv) {
	printf("My tiny calculator\n");
	if (setup_seccomp() != 0) {
		fprintf(stderr, "setup of seccomp failed!\n");
		return -1;
	}
	calcloop();
	return 0;
}
