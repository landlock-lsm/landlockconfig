/* SPDX-License-Identifier: Apache-2.0 OR MIT */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>

#include <landlock-policy.h>

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd, const int flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

int main(int argc, char *argv[], char *envp[])
{
	int policy_fd, ruleset_fd;
	struct landlock_policy *policy;
	const char *policy_file;
	struct stat st;

	if (argc <= 2) {
		fprintf(stderr, "Error: Missing policy file or command.\n\n");
		fprintf(stderr, "usage: %s <policy_file> <command> [args...]\n", argv[0]);
		return 1;
	}

	policy_file = argv[1];

	policy_fd = open(policy_file, O_RDONLY | O_CLOEXEC);
	if (policy_fd < 0) {
		perror("Failed to open policy file");
		return 1;
	}

	if (fstat(policy_fd, &st) < 0) {
		perror("Failed to stat policy file");
		close(policy_fd);
		return 1;
	}
	if (S_ISDIR(st.st_mode)) {
		close(policy_fd);
		policy = landlock_policy_parse_toml_directory(policy_file, 0);
	} else {
		policy = landlock_policy_parse_toml_file(policy_fd, 0);
		close(policy_fd);
	}

	if ((long)policy <= 0) {
		fprintf(stderr, "Failed to parse policy in '%s': %s\n",
			policy_file, strerror(-(long)policy));
		return 1;
	}

	ruleset_fd = landlock_policy_build_ruleset(policy, 0);
	landlock_policy_free(policy);
	if (ruleset_fd < 0) {
		fprintf(stderr, "Failed to build ruleset: %s\n",
			strerror(-ruleset_fd));
		return 1;
	}

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("Failed to restrict privileges");
		goto err_close_ruleset;
	}

	if (landlock_restrict_self(ruleset_fd, 0)) {
		perror("Failed to enforce ruleset");
		goto err_close_ruleset;
	}
	close(ruleset_fd);

	execvp(argv[2], &argv[2]);
	perror("Failed to execute command");
	return 1;

err_close_ruleset:
	close(ruleset_fd);
	return 1;
}
