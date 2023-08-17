// =====================================
//   ERROR HANDING - FROM FCUTILS
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
//   COMMAND LINE UTILITY
// =============================================


#include "wg2sd.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <grp.h>

[[noreturn]] void die_usage(char const * prog) {
	err("Usage: %s [ -o OUTPUT_PATH ] CONFIG_FILE", prog);
	die("Use -h for help");
}

void print_help(char const * prog) {
	err("Usage: %s [ -o OUTPUT_PATH ] CONFIG_FILE", prog);
	err("Options:");
	err("-o OUTPUT_PATH\tSet the output path (default is /etc/systemd/network)");
	err("-h\t\tDisplay this help message");
	exit(EXIT_SUCCESS);
}

using namespace wg2sd;

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

int main(int argc, char ** argv) {
	int opt;
	std::filesystem::path output_path = "/etc/systemd/network";

	while ((opt = getopt(argc, argv, "o:h")) != -1) {
		switch (opt) {
			case 'o':
				output_path = optarg;
				break;
			case 'h':
				print_help(argv[0]);
				break;
			default: /* '?' */
				die_usage(argv[0]);
		}
	}

	if (optind >= argc) {
		die_usage(argv[0]);
	}

	std::filesystem::path config_path = argv[optind];
	std::fstream cfg_stream { config_path };

	if(!cfg_stream.is_open()) {
		die("Failed to open config file %s", config_path.string().c_str());
	}

	std::string interface_name = interface_name_from_filename(config_path);

	SystemdConfig cfg;

	try {
		cfg = wg2sd::wg2sd(interface_name, cfg_stream, output_path);
	} catch(ConfigurationException const & cex) {

		const ParsingException * pex = dynamic_cast<const ParsingException *>(&cex);
		if(pex && pex->line_no().has_value()) {
			die("parsing error (line %llu): %s", pex->line_no().value(), pex->what());
		} else {
			die("configuration error: %s", cex.what());
		}

	}

	if(!std::filesystem::path(output_path).is_absolute()) {
		output_path = std::filesystem::absolute(output_path);
	}

	write_systemd_file(cfg.netdev, output_path, false);
	write_systemd_file(cfg.network, output_path, false);
	write_systemd_file(cfg.private_keyfile, output_path, true);

	for(SystemdFilespec const & spec : cfg.symmetric_keyfiles) {
		write_systemd_file(spec, output_path, true);
	}

	return 0;
}
