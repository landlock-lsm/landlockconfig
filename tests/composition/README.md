# Composition of configurations

## [TOML source #1](source/s1.toml)

```toml
[[variable]]
name = "rw"
literal = ["/tmp", "/var/tmp"]

# Main system file hierarchies can be read and executed.
[[path_beneath]]
allowed_access = ["v5.read_execute"]
parent = ["/bin", "/lib", "/usr", "/dev", "/proc", "/etc"]

# Only allow writing to temporary and home directories.
[[path_beneath]]
allowed_access = ["v5.read_write"]
parent = ["${rw}"]
```

## [TOML source #2](source/s2.toml)

```toml
[[variable]]
name = "rw"
literal = ["/home/user/tmp"]

[[ruleset]]
handled_access_fs = ["v4.all"]

# Custom apps.
[[path_beneath]]
allowed_access = ["v4.read_execute"]
parent = ["/home/user/bin"]
```

## [TOML composition](s.toml)

```toml
[[variable]]
name = "rw"
literal = ["/tmp", "/var/tmp", "/home/user/tmp"]

# Main system file hierarchies can be read and executed.
[[path_beneath]]
allowed_access = ["v4.read_execute"]
parent = ["/bin", "/lib", "/usr", "/dev", "/proc", "/etc", "/home/user/bin"]

# Only allow writing to temporary and home directories.
[[path_beneath]]
allowed_access = ["v4.read_write"]
parent = ["${rw}"]
```

## [JSON composition](s.json)

```json
{
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
        "v4.read_execute"
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
        "v4.read_write"
      ],
      "parent": [
        "${rw}"
      ]
    }
  ]
}
```
