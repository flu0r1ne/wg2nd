#pragma once

#include <istream>
#include <exception>
#include <optional>
#include <string>
#include <vector>
#include <filesystem>

#include <cstdint>

namespace wg2sd {

	struct Interface {
		// File name, or defaults to "wg"
		std::string name;
		// Address=...
		// List of ip addresses to be assigned to the interface
		std::vector<std::string> addresses;
		// PrivateKey=...
		// Base64-encoded private key string
		std::string private_key;
		// MTu=..
		std::string mtu;
		// DNS=...
		// DNS consists of a comma-separated list of IP addresses of DNS servers
		std::vector<std::string> DNS;
		// Table=...
		// By default, wireguard creates routes. This is disabled, when Table=off
		bool should_create_routes;
		// Table number (if specific), 0 if auto
		uint32_t table;
		// ListenPort=...
		// The port number on which the interface will listen
		std::optional<uint16_t> listen_port;
		// PreUp, PostUp, PreDown PostDown
		std::string preup, postup, predown, postdown;
		// SaveConfig
		std::string save_config;

		Interface()
			: should_create_routes { false }
			, table { 0 }
			, listen_port { }
		{ }
	};

	struct Cidr {
		std::string route;
		bool is_default_route;
		bool is_ipv4;
	};

	struct Peer {
		// Endpoint=...
		// IP and port of the peer
		std::string endpoint;
		// PublicKey=...
		std::string public_key;
		// AllowedIPs=...
		// Comma separated list of allowed ips
		// Each allowed ip is a CIDR block
		std::vector<Cidr> allowed_ips;
		// PersistentAlive=...
		std::string persistent_keepalive;
		// PresharedKey=...
		std::string preshared_key;
	};

	struct Config {
		// [Interface]
		Interface intf;
		// [Peer]
		std::vector<Peer> peers;
		// If one of the peers has a default route
		bool has_default_route;

		Config()
			: has_default_route { false }
		{ }
	};

	class ConfigurationException : public std::exception {

		public:

			ConfigurationException(std::string const & message)
				: _message { message }
			{}

			char const * what() const noexcept override {
				return _message.c_str();
			}

		private:
			std::string _message;
	};

	class ParsingException : public ConfigurationException {

		public:

			ParsingException(std::string const & message, std::optional<uint64_t> line_no = {})
				: ConfigurationException(message)
				, _line_no { line_no }
			{}


			std::optional<uint64_t> line_no() const noexcept {
				return _line_no;
			}

		private:
			std::string _message;
			std::optional<uint64_t> _line_no;
	};

	struct SystemdFilespec {
		std::string name;
		std::string contents;
	};

	struct SystemdConfig {
		SystemdFilespec netdev;
		SystemdFilespec network;
		SystemdFilespec private_keyfile;
		std::vector<SystemdFilespec> symmetric_keyfiles;

		std::vector<std::string> warnings;
	};

	std::string interface_name_from_filename(std::filesystem::path config_path);

	Config parse_config(std::string const & interface_name, std::istream & stream);

	SystemdConfig gen_systemd_config(Config const & cfg, std::string const & output_path);

	SystemdConfig wg2sd(std::string const & interface_name, std::istream & stream, std::string const & output_path);

};
