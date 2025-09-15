/* SPDX-License-Identifier: Apache-2.0 OR MIT */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <syscall.h>
#include <unistd.h>

#include <landlockconfig.h>

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd, const int flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

int main(int argc, char *argv[], char *envp[])
{
	int config_fd, ruleset_fd;
	struct landlockconfig *config;
	const char *config_file;
	struct stat st;

	if (argc <= 2) {
		fprintf(stderr, "Error: Missing config file or command.\n\n");
		fprintf(stderr, "usage: %s <config_file> <command> [args...]\n", argv[0]);
		return 1;
	}

	config_file = argv[1];

	config_fd = open(config_file, O_RDONLY | O_CLOEXEC);
	if (config_fd < 0) {
		perror("Failed to open configuration file");
		return 1;
	}

	if (fstat(config_fd, &st) < 0) {
		perror("Failed to stat configuration file");
		close(config_fd);
		return 1;
	}
	if (S_ISDIR(st.st_mode)) {
		close(config_fd);
		config = landlockconfig_parse_toml_directory(config_file, 0);
	} else {
		config = landlockconfig_parse_toml_file(config_fd, 0);
		close(config_fd);
	}

	if ((long)config <= 0) {
		fprintf(stderr, "Failed to parse configuration in '%s': %s\n",
			config_file, strerror(-(long)config));
		return 1;
	}

	ruleset_fd = landlockconfig_build_ruleset(config, 0);
	landlockconfig_free(config);
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
