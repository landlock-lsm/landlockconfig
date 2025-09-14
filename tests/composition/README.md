# Composition of configurations

## [TOML source #1](source/s1.toml)

```toml
abi = 5

[[variable]]
name = "rw"
literal = ["/tmp", "/var/tmp"]

# Main system file hierarchies can be read and executed.
[[path_beneath]]
allowed_access = ["abi.read_execute"]
parent = ["/bin", "/lib", "/usr", "/dev", "/proc", "/etc"]

# Only allow writing to temporary and home directories.
[[path_beneath]]
allowed_access = ["abi.read_write"]
parent = ["${rw}"]
```

## [TOML source #2](source/s2.toml)

```toml
abi = 4

[[variable]]
name = "rw"
literal = ["/home/user/tmp"]

[[ruleset]]
handled_access_fs = ["abi.all"]

# Custom apps.
[[path_beneath]]
allowed_access = ["abi.read_execute"]
parent = ["/home/user/bin"]
```

## [TOML composition](s.toml)

```toml
abi = 4

[[variable]]
name = "rw"
literal = ["/tmp", "/var/tmp", "/home/user/tmp"]

# Main system file hierarchies can be read and executed.
[[path_beneath]]
allowed_access = ["abi.read_execute"]
parent = ["/bin", "/lib", "/usr", "/dev", "/proc", "/etc", "/home/user/bin"]

# Only allow writing to temporary and home directories.
[[path_beneath]]
allowed_access = ["abi.read_write"]
parent = ["${rw}"]
```

## [JSON composition](s.json)

```json
{
  "abi": 4,
  "variable": [
    {
      "name": "rw",
      "literal": [
        "/tmp",
        "/var/tmp",
        "/home/user/tmp"
      ]
    }
  ],
  "pathBeneath": [
    {
      "allowedAccess": [
        "abi.read_execute"
      ],
      "parent": [
        "/bin",
        "/lib",
        "/usr",
        "/dev",
        "/proc",
        "/etc",
        "/home/user/bin"
      ]
    },
    {
      "allowedAccess": [
        "abi.read_write"
      ],
      "parent": [
        "${rw}"
      ]
    }
  ]
}
```
