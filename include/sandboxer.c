/* SPDX-License-Identifier: Apache-2.0 OR MIT */

#include <fcntl.h>
#include <stdio.h>
#include <syscall.h>
#include <unistd.h>
#include <sys/prctl.h>

#include "landlockconfig.h"

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd,
                                         const int flags) {
  return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif

int main(int argc, char *argv[], char *envp[]) {
  int config_fd, ruleset_fd;
  struct landlockconfig *config;

  config_fd = open("config.toml", O_RDONLY | O_CLOEXEC);
  if (config_fd < 0) {
    perror("Failed to open config");
    return 1;
  }

  config = landlockconfig_parse_toml(config_fd);
  close(config_fd);
  if ((long)config <= 0) {
    perror("Failed to parse config");
    return 1;
  }
  // fprintf(stderr, "OK config:%p\n", config);

  ruleset_fd = landlockconfig_build_ruleset(config);
  landlockconfig_free(config);
  if (ruleset_fd < 0) {
    perror("Failed to restrict");
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

  if (execve("/bin/bash", (char *[]){"/bin/bash", "-i", NULL}, envp) < 0) {
    perror("Failed to execute Bash");
    return 1;
  }

err_close_ruleset:
    close(ruleset_fd);
    return 1;
}
