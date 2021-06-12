#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>


int setup_seccomp() {
	scmp_filter_ctx ctx;
	ctx = seccomp_init(SCMP_ACT_KILL);
	if (ctx == NULL) {
		return -1;
	}
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 1, 
			SCMP_CMP(0, SCMP_CMP_EQ, STDIN_FILENO)) < 0) {
		seccomp_release(ctx);
		fprintf(stderr, "could not setup rule for read\n");
		return -1;
	}
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 1, 
			SCMP_CMP(0, SCMP_CMP_EQ, STDOUT_FILENO)) < 0) {
		seccomp_release(ctx);
		fprintf(stderr, "could not setup rule for write\n");
		return -1;
	}
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fstat), 1, 
			SCMP_CMP(0, SCMP_CMP_EQ, STDIN_FILENO)) < 0) {
		seccomp_release(ctx);
		fprintf(stderr, "could not setup rule for fstat\n");
		return -1;
	}
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(lseek), 2,
			SCMP_CMP(0, SCMP_CMP_EQ, STDIN_FILENO),
			SCMP_CMP(2, SCMP_CMP_EQ, SEEK_CUR)) < 0) {
		seccomp_release(ctx);
                fprintf(stderr, "could not setup rule for lseek\n");
		return -1;
	}
	if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 1, 
			SCMP_CMP(0, SCMP_CMP_EQ, 0)) < 0) {
		seccomp_release(ctx);
		fprintf(stderr, "could not setup rule for exit_group\n");
		return -1;
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
