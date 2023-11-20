// SPDX-License-Identifier: GPL-2.0 OR MIT

/*
 * Copyright (C) 2023 Alex David <flu0r1ne@flu0r1ne.net>
 */

#include "version.hpp"

#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <getopt.h>

// =====================================
//	 ERROR HANDING - FROM FCUTILS
// =====================================

#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define FORMAT_MAX_SIZE 1024
extern int errno;

void format_with_errno(char * buf, size_t n, char const * format) {
	char const * errstr = strerror(errno);
	char fmt_err[256];

	size_t i = 0,
		   j = 0;
	while(errstr[j] && i < sizeof(fmt_err) - 1) {
		if((fmt_err[i++] = errstr[j++]) != '%')
			continue;

		if(i < sizeof(fmt_err) - 1) {
			fmt_err[i++] = '%';
		} else {
			i--;
		}
	}

	fmt_err[i] = '\0';

	snprintf(buf, n, "%s: %s", format, fmt_err);
}


[[noreturn]] void die_errno(char const * format, ...) {
	va_list vargs;
	va_start (vargs, format);

	char buf[FORMAT_MAX_SIZE];
	format_with_errno(buf, sizeof(buf), format);
	vfprintf(stderr, buf, vargs);
	fprintf(stderr, "\n");
	exit(1);

	va_end(vargs);
}

[[noreturn]] void die(char const * format, ...) {
	va_list vargs;
	va_start (vargs, format);

	vfprintf(stderr, format, vargs);
	fprintf(stderr, "\n");

	va_end(vargs);
	exit(1);
}

void err(char const * format, ...) {
	va_list vargs;
	va_start (vargs, format);

	vfprintf(stderr, format, vargs);
	fprintf(stderr, "\n");

	va_end(vargs);
}

// =============================================
//	 COMMAND LINE UTILITY
// =============================================

constexpr char const * DEFAULT_OUTPUT_PATH = "/etc/systemd/network/";

/*
 * HELP AND USAGE
 */

void die_usage(const char *prog) {
	err("Usage: %s {  install, generate } [ OPTIONS ] { -h, CONFIG_FILE }", prog);
	err("Usage: %s version", prog);
	die("Use -h for help");
}

void print_help(const char *prog) {
	err("Usage: %s { install, generate } [ OPTIONS ] { -h, CONFIG_FILE }", prog);
	err("Usage: %s version\n", prog);
	err("  CONFIG_FILE is the complete path to a WireGuard configuration file, used by");
	err("  `wg-quick`. `wg2nd` will convert the WireGuard configuration to networkd");
	err("  files.\n");
	err("  The generated configurations are functionally equivalent to `wg-quick(8)`");
	err("  with the following exceptions:\n");
	err("  1. When unspecified, `wg-quick` determines whether `FwMark` and `Table` are available dynamically,");
	err("     ensuring that the routing table and `fwmark` are not already in use. `wg2nd` sets");
	err("     the `fwmark` to a random number (deterministically generated from the interface");
	err("     name). If more than 500 `fwmarks` are in use, there is a non-negligible chance of a");
	err("     collision. This would occur when there are more than 500 active WireGuard interfaces.\n");
	err("  2. The PreUp, PostUp, PreDown, and PostDown script snippets are ignored.\n");
	err("  3. `wg-quick(8)` installs a firewall when a default route is specified (i.e., when `0.0.0.0/0`");
	err("     or `::/0` are specified in `AllowedIPs`). This is not installed by");
	err("     default with `wg2nd install`. The equivalent firewall can be generated with");
	err("     `wg2nd generate -t nft CONFIG_FILE`. Refer to `nft(8)` for details.\n");
	err("  Actions:");
	err("    install   Generate and install the configuration with restricted permissions");
	err("    generate  Generate specific configuration files and write the results to stdout\n");
	err("  Options:");
	err("    -h        Print this help");
	exit(EXIT_SUCCESS);
}

void die_usage_generate(const char *prog) {
	err("Usage: %s generate [ -h ] [ -k KEYPATH ] [ -t { network, netdev, keyfile, nft } ] CONFIG_FILE", prog);
	die("Use -h for help");
}

void print_help_generate(const char *prog) {
	err("Usage: %s generate [ -h ] [ -k KEYPATH ] [ -t { network, netdev, keyfile, nft } ] CONFIG_FILE\n", prog);
	err("Options:");
	err("  -t FILE_TYPE");
	err("     network  Generate a Network Configuration File (see systemd.network(8))");
	err("     netdev   Generate a Virtual Device File (see systemd.netdev(8))");
	err("     keyfile  Print the interface's private key");
	err("     nft      Print the netfilter table `nft(8)` installed by `wg-quick(8)`\n");
	err("  -k KEYPATH  Full path to the keyfile (a path relative to /etc/systemd/network is generated");
	err("              if unspecified)\n");
	err("  -h        Print this help");
	exit(EXIT_SUCCESS);
}

void die_usage_install(const char *prog) {
	err("Usage: %s install [ -h ] [ -f FILE_NAME ] [ -k KEYFILE ] [ -o OUTPUT_PATH ] CONFIG_FILE", prog);
	die("Use -h for help");
}

void print_help_install(const char *prog) {
	err("Usage: %s install [ -h ] [ -f FILE_NAME ] [ -o OUTPUT_PATH ] CONFIG_FILE\n", prog);
	err("  `wg2nd install` translates `wg-quick(8)` configuration into corresponding");
	err("  `networkd` configuration and installs the resulting files in `OUTPUT_PATH`.\n");
	err("  `wg2nd install` generates a `netdev`, `network`, and `keyfile` for each");
	err("  CONFIG_FILE. Links will be installed with a `manual` `ActivationPolicy`.");
	err("  The interface can be brought up with `networkctl up INTERFACE` and down");
	err("  with `networkctl down INTERFACE`.\n");
	err("  `wg-quick(8)` installs a firewall when a default route (i.e., when `0.0.0.0/0`");
	err("  or `::/0` is specified in `AllowedIPs`). This is not installed by default");
	err("  with `wg2nd install`. The equivalent firewall can be generated with");
	err("  `wg2nd generate -t nft CONFIG_FILE`.\n");
	err("Options:");
	err("  -o OUTPUT_PATH  The installation path (default is /etc/systemd/network)\n");
	err("  -f FILE_NAME    The base name for the installed configuration files. The");
	err("                  networkd-specific configuration suffix will be added");
	err("                  (FILE_NAME.netdev for systemd-netdev(8) files,");
	err("                  FILE_NAME.network for systemd-network(8) files,");
	err("                  and FILE_NAME.keyfile for keyfiles)\n");
	err("  -k KEYFILE       The name of the private keyfile\n");
	err("  -h              Print this help");
	exit(EXIT_SUCCESS);
}


/*
 * PARSING
 */

enum class FileType {
	NONE = 0,
	NETWORK,
	NETDEV,
	KEYFILE,
	NFT
};


/*
 * INTERNAL LOGIC
 */

#include "wg2nd.hpp"

#include <iostream>
#include <fstream>
#include <optional>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <grp.h>

using namespace wg2nd;

void write_systemd_file(SystemdFilespec const & filespec, std::string output_path, bool secure) {
	std::string full_path = output_path + "/" + filespec.name;
	std::ofstream ofs;

	if (secure) {
		// Set permissions to 0640 before writing the file
		umask(0027);

		// Open the file
		ofs.open(full_path, std::ios::out | std::ios::trunc);
		if (!ofs.is_open()) {
			die("Failed to open file %s for writing", full_path.c_str());
		}

		// Change ownership to root:systemd-network
		struct group *grp;
		grp = getgrnam("systemd-network");
		if (grp == nullptr) {
			die_errno("Failed to find the 'systemd-network' group");
		}
		if (chown(full_path.c_str(), 0, grp->gr_gid) != 0) {
			die_errno("Failed to change ownership of file %s", full_path.c_str());
		}

		// Set permissions
		if (chmod(full_path.c_str(), S_IRUSR | S_IWUSR | S_IRGRP) != 0) {
			die_errno("Failed to set permissions for file %s", full_path.c_str());
		}
	} else {
		ofs.open(full_path, std::ios::out | std::ios::trunc);
		if (!ofs.is_open()) {
			die_errno("Failed to open file %s for writing", full_path.c_str());
		}
	}

	// Write the contents to the file
	ofs << filespec.contents;

	if (ofs.fail()) {
		die("Failed to write to file %s", full_path.c_str());
	}
}

SystemdConfig generate_cfg_or_die(
	std::filesystem::path && config_path,
	std::filesystem::path const & keyfile_or_output_path,
	std::optional<std::string> const & filename
	) {
	std::fstream cfg_stream { config_path };

	if(!cfg_stream.is_open()) {
		die("Failed to open config file %s", config_path.string().c_str());
	}

	SystemdConfig cfg;

	std::string interface_name = interface_name_from_filename(config_path);

	try {
		cfg = wg2nd::wg2nd(interface_name, cfg_stream, keyfile_or_output_path, filename);
	} catch(ConfigurationException const & cex) {

		const ParsingException * pex = dynamic_cast<const ParsingException *>(&cex);
		if(pex && pex->line_no().has_value()) {
			die("parsing error (line %llu): %s", pex->line_no().value(), pex->what());
		} else {
			die("configuration error: %s", cex.what());
		}

	}

	return cfg;
}


void wg2nd_install_internal(std::optional<std::string> && filename, std::string && keyfile_name,
	std::filesystem::path && output_path, std::filesystem::path && config_path) {

	if(!std::filesystem::path(output_path).is_absolute()) {
		output_path = std::filesystem::absolute(output_path);
	}

	std::filesystem::path keyfile_or_output_path = output_path;

	if(!keyfile_name.empty()) {
		keyfile_or_output_path /= keyfile_name;
	}

	SystemdConfig cfg = generate_cfg_or_die(std::move(config_path), keyfile_or_output_path, std::move(filename));

	for(std::string const & warning : cfg.warnings) {
		err("warning: %s", warning.c_str());
	}

	write_systemd_file(cfg.netdev, output_path, false);
	write_systemd_file(cfg.network, output_path, false);
	write_systemd_file(cfg.private_keyfile, output_path, true);

	for(SystemdFilespec const & spec : cfg.symmetric_keyfiles) {
		write_systemd_file(spec, output_path, true);
	}
}

void wg2nd_generate_internal(FileType type, std::string && config_file,
	std::optional<std::filesystem::path> && keyfile_path) {

	SystemdConfig cfg = generate_cfg_or_die(
		std::move(config_file), std::move(keyfile_path.value_or(DEFAULT_OUTPUT_PATH)), {}
	);

	switch(type) {
		case FileType::NFT:
			printf("%s", cfg.firewall.c_str());
			break;
		case FileType::NETWORK:
			printf("%s", cfg.network.contents.c_str());
			break;
		case FileType::NETDEV:
			printf("%s", cfg.netdev.contents.c_str());
			break;
		case FileType::KEYFILE:
			printf("%s", cfg.private_keyfile.contents.c_str());
			break;
		default:
			break;
	}
}


static int wg2nd_generate(char const * prog, int argc, char **argv) {
	std::filesystem::path config_path = "";

	FileType type = FileType::NONE;
	std::optional<std::filesystem::path> keyfile_path = {};

	int opt;
	while ((opt = getopt(argc, argv, "ht:k:")) != -1) {
		switch (opt) {
			case 't':
				if (strcmp(optarg, "network") == 0) {
					type = FileType::NETWORK;
				} else if (strcmp(optarg, "netdev") == 0) {
					type = FileType::NETDEV;
				} else if (strcmp(optarg, "keyfile") == 0) {
					type = FileType::KEYFILE;
				} else if (strcmp(optarg, "nft") == 0) {
					type = FileType::NFT;
				} else {
					die("Unknown file type: %s", optarg);
				}
				break;
			case 'k':
				keyfile_path = optarg;
				break;
			case 'h':
				print_help_generate(prog);
				break;
			default:
				die_usage_generate(prog);
		}
	}

	if (optind >= argc) {
		die_usage_generate(prog);
	}

	config_path = argv[optind];

	wg2nd_generate_internal(type, std::move(config_path), std::move(keyfile_path));

	return 0;
}

static int wg2nd_install(char const * prog, int argc, char **argv) {
	std::filesystem::path config_path = "";

	std::optional<std::string> filename = {};
	std::filesystem::path output_path = DEFAULT_OUTPUT_PATH;
	std::string keyfile_name = "";

	int opt;
	while ((opt = getopt(argc, argv, "o:f:k:h")) != -1) {
		switch (opt) {
			case 'o': {
				std::string path = optarg;
				if(path[path.size() - 1] != '/') {
					path.push_back('/');
				}
				output_path = std::move(path);
				break;
			}
			case 'f':
				filename = optarg;
				break;
			case 'h':
				print_help_install(prog);
				break;
			case 'k':
				keyfile_name = optarg;
				break;
			default:
				die_usage_install(prog);
		}
	}

	if (optind >= argc) {
		die_usage_install(prog);
	}

	config_path = argv[optind];

	wg2nd_install_internal(std::move(filename), std::move(keyfile_name), std::move(output_path), std::move(config_path));

	return 0;
}

int main(int argc, char **argv) {
	char const * prog = "wg2nd";

	if(argc > 0) {
		prog = argv[0];
	}

	if (argc < 2) {
		die_usage(prog);
	}

	std::string action = argv[1];

	if (action == "generate") {
		return wg2nd_generate(prog, argc - 1, argv + 1);
	} else if (action == "install") {
		return wg2nd_install(prog, argc - 1, argv + 1);
	} else if (action == "version") {
		printf("%s\n", VERSION);
	} else if (action == "-h" || action == "--help") {
		print_help(prog);
	} else {
		err("Unknown action: %s", action.c_str());
		die_usage(prog);
	}

	return 0;
}
