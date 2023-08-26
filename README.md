wg2nd - WireGuard to systemd-networkd Configuration Converter
=============================================================

`wg2nd` is a specialized utility designed to convert WireGuard configurations in the `wg-quick(8)`
format into `systemd-networkd` compatible configurations. It serves as an intermediary tool,
facilitating the migration of functional configurations from `wg-quick` to `networkd`.

Purpose
-------

The primary purpose of `wg2nd` is to act as a bridge between the `wg-quick` utility and `networkd`. `networkd` is
a feature-complete network manager that offers more control over managing WireGuard tunnels. Additionally,
migrating these configurations to `networkd` can address reliability issues that may arise due to `networkd`
interfering with WireGuard tunnels it doesn't manage.

Compatibility and Limitations
-----------------------------

`wg2nd` is capable of translating almost all configurations without requiring additional configuration, although
exceptions may arise in certain situations. Notable technical distinctions include:

1. **Dynamic Firewall Installation**: `wg-quick(8)` automatically installs a firewall when a default route is specified
    (e.g., `0.0.0.0/0` or `::/0` in `AllowedIPs`). However, `wg2nd` does not perform this action by default when using
    the `install` command. Users can generate an equivalent firewall using the `wg2nd generate -t nft CONFIG_FILE` command
    and install it into a file accessible by `nft` (See `nft(8)` for details).

2. **Additional Scripting**: `wg2nd` ignores the `PreUp`, `PostUp`, `PreDown`, and `PostDown` script snippets recognized by
   `wg-quick`. These script snippets are not processed during the translation process. Users relying on these scripts should
   install them statically or manage them through `systemd`.

3. **FwMark and Table Handling**: While `wg-quick` dynamically determines the availability of `FwMark` and `Table` options,
   avoiding conflicts with existing routing tables and firewall marks, `wg2nd` generates the `fwmark` using a deterministic
   method based on the interface name. This scenario is highly unlikely. Concerns might arise if more than 500 interfaces
   using default routes are active simultaneously, but even then, the probability is low.

Installation
------------

To install `wg2nd`, please follow the instructions below based on your distribution:

### Ubuntu/Debian

```bash
sudo apt install build-essential libargon2-dev
make
sudo make install
```

### Arch Linux

```bash
sudo pacman -S argon2 make gcc
make
sudo make install
```

Example Usage
-------------

### Single Conversion

For converting a single WireGuard configuration file (`wg0.conf`) to `systemd-networkd` format
and installing it in `/etc/systemd/network/`, execute the following commands:

```bash
# Generate the networkd configuration
wg2nd install /etc/wireguard/wg0.conf

# Append firewall rules to nft(8)
wg2nd generate -t nft /etc/wireguard/wg0.conf >> /etc/nftables.conf

# Activate the network interface
networkctl up wg0
```

To enable automatic starting, ensure that the `ActivationPolicy` is removed from the generated `network` configuration.

### Batch Conversion

For batch converting all WireGuard configuration files in a directory (e.g., `/etc/wireguard/`),
run the following command as root:

```bash
for file in /etc/wireguard/*.conf; do
    wg2nd install $file
done

# Activate the network interface
networkctl up INTERFACE_NAME
```

Usage
-----

`wg2nd` provides two primary actions: `install` and `generate`. The `generate` subcommand generates
specific components of the configurations and outputs them to `stdout`. The `install` command
installs the configuration with the appropriate permissions.

```plaintext
Usage: ./wg2nd { install, generate } [ OPTIONS ] { -h, CONFIG_FILE }

  CONFIG_FILE is the complete path to a WireGuard configuration file used by
  `wg-quick`. `wg2nd` converts the WireGuard configuration to networkd files.

  The generated configurations are functionally equivalent to `wg-quick(8)`
  with the following exceptions:

  1. When unspecified, `wg-quick` determines whether `FwMark` and `Table` are available dynamically,
     ensuring that the routing table and `fwmark` are not already in use. `wg2nd` sets
     the `fwmark` to a random number (deterministically generated from the interface
     name). If more than 500 `fwmarks` are in use, there is a non-negligible chance of a
     collision. This would occur when there are more than 500 active WireGuard interfaces.

  2. The PreUp, PostUp, PreDown, and PostDown script snippets are ignored.

  3. `wg-quick(8)` installs a firewall when a default route is specified (i.e., when `0.0.0.0/0`
     or `::/0` are specified in `AllowedIPs`). This is not installed by
     default with `wg2nd install`. The equivalent firewall can be generated with
     `wg2nd generate -t nft CONFIG_FILE`. Refer to `nft(8)` for details.

  Actions:
    install   Generate and install the configuration with restricted permissions
    generate  Generate specific configuration files and write the results to stdout

  Options:
    -h        Print this help
```

```plaintext
Usage: ./wg2nd install [ -h ] [ -f FILE_NAME ] [ -o OUTPUT_PATH ] CONFIG_FILE

  `wg2nd install` translates `wg-quick(8)` configuration into corresponding
  `networkd` configuration and installs the resulting files in `OUTPUT_PATH`.

  `wg2nd install` generates a `netdev`, `network`, and `keyfile` for each
  CONFIG_FILE. Links will be installed with a `manual` `ActivationPolicy`.
  The interface can be brought up with `networkctl up INTERFACE` and down
  with `networkctl down INTERFACE`.

  `wg-quick(8)` installs a firewall when a default route (i.e., when `0.0.0.0/0`
  or `::/0` is specified in `AllowedIPs`). This is not installed by default
  with `wg2nd install`. The equivalent firewall can be generated with
  `wg2nd generate -t nft CONFIG_FILE`.

Options:
  -o OUTPUT_PATH  The installation path (default is /etc/systemd/network)

  -f FILE_NAME    The base name for the installed configuration files. The
                  networkd-specific configuration suffix will be added
                  (FILE_NAME.netdev for systemd-netdev(8) files,
                  FILE_NAME.network for systemd-network(8) files,
                  and FILE_NAME.keyfile for keyfiles)

  -k KEYFILE       The name of the private keyfile

  -h              Print this help
```

```plaintext
Usage: wg2nd generate [ -h ] [ -t { network, netdev, keyfile, nft } ] CONFIG_FILE

`wg2nd generate` translates `wg-quick(8)` configuration into the equivalent
`systemd-networkd` configuration. The results are printed to `stdout`. Users
are responsible for installing these files correctly and restricting access privileges.

Options:
  -t FILE_TYPE
     network    Generate a Network Configuration File (see systemd.network(8))
     netdev     Generate a Virtual Device File (see systemd.netdev(8))
     keyfile    Print the interface's private key
     nft        Print the netfilter table `nft(8)` installed by `wg-quick(8)`

  -h            Display this help
```
