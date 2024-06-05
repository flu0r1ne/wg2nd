// SPDX-License-Identifier: GPL-2.0 OR MIT

/*
 * Copyright (C) 2023 Alex David <flu0r1ne@flu0r1ne.net>
 */

#include "wg2nd.hpp"

#include <exception>
#include <sstream>
#include <random>
#include <regex>

#include <string_view>

#include "crypto/pubkey.hpp"

extern "C" {
	#include "crypto/halfsiphash.h"
}

constexpr char const * PRIVATE_KEY_SUFFIX = ".privkey";
constexpr char const * SYMMETRIC_KEY_SUFFIX = ".symkey";


namespace wg2nd {
	std::string private_keyfile_name(std::string const & priv_key) {
		char pub_key[WG_KEY_LEN_BASE32];

		// Derive public key
		if(wg_pubkey_base32(priv_key.c_str(), pub_key)) {
			throw ParsingException("Private key is formatted improperly");
		}

		std::string keyfile_name { pub_key };
		keyfile_name.append(PRIVATE_KEY_SUFFIX);

		return keyfile_name;
	}

	std::string public_keyfile_name(std::string const & pub_key) {
		char pub_key32[WG_KEY_LEN_BASE32];

		if(wg_key_convert_base32(pub_key.c_str(), pub_key32)) {
			throw ParsingException("Public key for [Peer] " + pub_key + " is formatted improperly");
		}

		std::string keyfile_name { pub_key32 };
		keyfile_name.append(SYMMETRIC_KEY_SUFFIX);

		return keyfile_name;
	}

	uint32_t deterministic_fwmark(std::string const & interface_name) {
		constexpr uint8_t const SIP_KEY[8] = {
			0x90, 0x08, 0x82, 0xd7,
			0x75, 0x68, 0xf4, 0x8e,
		};

		uint32_t mark;

		halfsiphash(interface_name.c_str(), interface_name.size(), SIP_KEY, (uint8_t *) &mark, sizeof(mark));

		return mark;
	}

	std::string interface_name_from_filename(std::filesystem::path config_path) {
		std::string interface_name = config_path.filename().string();
		interface_name = interface_name.substr(
			0, interface_name.size() - config_path.extension().string().size()
		);
		return interface_name;
	}

	bool _is_default_route(std::string const & cidr) {
		static std::regex ipv4_wildcard("0(\\.0){0,3}\\/0");
		static std::regex ipv6_wildcard("(0{0,4}:){0,7}0{0,4}\\/0{1,4}");
		
		return std::regex_match(cidr, ipv4_wildcard) or std::regex_match(cidr, ipv6_wildcard);
	}

	bool _is_ipv4_route(std::string const & cidr) {
		static std::regex ipv4("\\d{1,3}(\\.\\d{1,3}){0,3}(\\/\\d{1,2})?");

		return std::regex_match(cidr, ipv4);
	}

	std::string_view _get_addr(std::string_view const & cidr) {
		size_t suffix = cidr.rfind('/');

		if(suffix == std::string::npos) {
			return cidr;
		} else {
			return cidr.substr(0, suffix);
		}
	}

	constexpr uint32_t MAIN_TABLE = 254;
	constexpr uint32_t LOCAL_TABLE = 255;

	// Parse the wireguard configuration from an input stream
	// into a Config object. If an invalid key or section occurs,
	// exists, a ParsingException is thrown.
	Config parse_config(std::string const & interface_name, std::istream & stream) {
		Config cfg;

		cfg.intf.name = interface_name;
		cfg.has_default_route = false;
		cfg.intf.should_create_routes = true;

		std::string line;
		uint64_t line_no = 0;

		enum class Section {
			Interface,
			Peer,
			None
		};

		Section section = Section::None;

		bool peer_has_default_route = false;

		while (std::getline(stream, line)) {
			++line_no;

			// Strip whitespace (\t) from line in-place
			{
				size_t i = 0, j = 0;
				for(; i < line.size(); i++) {
					if(line[i] != ' ' and line[i] != '\t' and line[i] != '\r') {
						line[j] = line[i];
						j++;
					}
				}
				line.erase(j);
			}

			// Remove content exceeding a comment
			size_t comment_start = line.find('#');
			if(comment_start != std::string::npos) {
				line.erase(comment_start);
			}

			// Ignore empty lines
			if (line.empty()) {
				continue;
			}

			// Handle section: [Interface] or [Peer] specifies further
			// configuration concerns an interface or peer respectively
			
			bool interface_sec_wanted = line == "[Interface]";
			bool peer_sec_wanted = line == "[Peer]";

			if(interface_sec_wanted || peer_sec_wanted) {
				cfg.has_default_route = cfg.has_default_route or peer_has_default_route;
				peer_has_default_route = false;
			}

			if (interface_sec_wanted) {
				section = Section::Interface;
				continue;
			} else if (peer_sec_wanted) {
				section = Section::Peer;
				cfg.peers.emplace_back();
				continue;
			}

			// Split key
			size_t pos = line.find('=');
			if(pos == std::string::npos) {
				throw ParsingException("Expected key-value pair, got \"" + line + "\"", line_no);
			}

			std::string key = line.substr(0, pos);
			std::string value = line.substr(pos + 1);

			// Read keys according to corresponding section
			switch (section) {
			case Section::Interface: {
				if (key == "PrivateKey") {
					cfg.intf.private_key = value;
				} else if (key == "DNS") {
					std::istringstream dnsStream(value);
					std::string dnsIp;
					while (std::getline(dnsStream, dnsIp, ',')) {
						cfg.intf.DNS.push_back(dnsIp);
					}
				} else if (key == "Address") {
					std::istringstream addressStream(value);
					std::string address;
					while (std::getline(addressStream, address, ',')) {
						cfg.intf.addresses.push_back(address);
					}
				} else if (key == "Table") {
					if(value == "off") {
						cfg.intf.table = 0;
						cfg.intf.should_create_routes = false;
					} else {
						cfg.intf.should_create_routes = true;
						if(value == "auto") {
							cfg.intf.table = 0;
						} else if(value == "main") {
							cfg.intf.table = MAIN_TABLE;
						} else if(value == "local") {
							cfg.intf.table = LOCAL_TABLE;
						} else {
							long long table;
							try {
								table = std::stoll(value);
							} catch(std::exception const & e) {
								table = -1;
							}

							if(table < 1 || table > UINT32_MAX) {
								throw ParsingException("Invalid option to \"Table\", must be one of \"off\", \"auto\" or a table number", line_no);
							}

							cfg.intf.table = table;
						}
					}
				} else if (key == "ListenPort") {
					int port;
					try {
						port = std::stoi(value);
					} catch(std::exception & e) {
						port = -1;
					}

					if(port < 0 || port > UINT16_MAX) {
						throw ParsingException("Invalid port: " + key, line_no);
					}

					cfg.intf.listen_port = port;
				} else if (key == "MTU") {
					cfg.intf.mtu = value;
				} else if (key == "PreUp") {
					cfg.intf.preup = value;
				} else if (key == "PostUp") {
					cfg.intf.postup = value;
				} else if (key == "PreDown") {
					cfg.intf.predown = value;
				} else if (key == "PostDown") {
					cfg.intf.postdown = value;
				} else if (key == "SaveConfig") {
					cfg.intf.save_config = value;
				} else {
					throw ParsingException("Invalid key in [Interface] section: " + key, line_no);
				}
				break;
			}
			case Section::Peer: {
				if (key == "Endpoint") {
					cfg.peers.back().endpoint = value;
				} else if (key == "AllowedIPs") {
					std::istringstream allowedIpsStream(value);
					std::string allowedIp;

					while (std::getline(allowedIpsStream, allowedIp, ',')) {
						bool is_default_route = _is_default_route(allowedIp);

						if(is_default_route and cfg.has_default_route) {
							throw ParsingException("Default routes exist on multiple peers");
						}
						
						cfg.peers.back().allowed_ips.push_back(Cidr {
							.route = allowedIp,
							.is_default_route = is_default_route,
							.is_ipv4 = _is_ipv4_route(allowedIp),
						});

						peer_has_default_route = peer_has_default_route or is_default_route;
					}

				} else if (key == "PublicKey") {
					cfg.peers.back().public_key = value;
				} else if (key == "PersistentKeepalive") {
					cfg.peers.back().persistent_keepalive = value;
				} else if (key == "PresharedKey") {
					cfg.peers.back().preshared_key = value;
				} else {
					throw ParsingException("Invalid key in [Peer] section: " + key, line_no);
				}
				break;
			}
			case Section::None:
				throw ParsingException("Unexpected key outside of section: " + key, line_no);
			}
		}

		cfg.has_default_route = cfg.has_default_route or peer_has_default_route;

#define MissingField(section, key) \
	ConfigurationException("[" section "] section missing essential field \"" key "\"")

		// Ensure PrivateKey, Address, PublicKey, and AllowedIPs are present

		if(cfg.intf.private_key.empty()) {
			throw MissingField("Interface", "PrivateKey");
		}

		if(cfg.intf.addresses.empty()) {
			throw MissingField("Interface", "Address");
		}

		for(Peer const & peer : cfg.peers) {
			if(peer.public_key.empty()) {
				throw MissingField("Peer", "PublicKey");
			}

			if(peer.allowed_ips.empty()) {
				throw MissingField("Peer", "AllowedIPs");
			}
		}

#undef MissingField

		return cfg;
	}

	static void _write_table(std::stringstream & firewall, Config const & cfg, std::vector<std::string_view> addrs, bool ipv4, uint32_t fwd_table) {
		char const * ip = ipv4 ? "ip" : "ip6";

		firewall << "table " << ip << " " << cfg.intf.name << " {\n"
		         << "  chain preraw {\n"
		         << "    type filter hook prerouting priority raw; policy accept;\n";

		for(std::string_view const & addr : addrs) {
			firewall << "    iifname != \"" << cfg.intf.name << "\" " << ip << " daddr " << addr << " fib saddr type != local drop;\n";
		}

		firewall << "  }\n"
		         << "\n"
		         << "  chain premangle {\n"
		         << "    type filter hook prerouting priority mangle; policy accept;\n"
		         << "    meta l4proto udp meta mark set ct mark;\n"
		         << "  }\n"
		         << "\n"
		         << "  chain postmangle {\n"
		         << "    type filter hook postrouting priority mangle; policy accept;\n"
		         << "    meta l4proto udp meta mark 0x" << std::hex << fwd_table << std::dec << " ct mark set meta mark;\n"
		         << "  }\n"
		         << "}\n";
		
	}

	std::string _gen_nftables_firewall(Config const & cfg, uint32_t fwd_table) {
		std::stringstream firewall;

		std::vector<std::string_view> ipv4_addrs;
		std::vector<std::string_view> ipv6_addrs;

		for(std::string const & addr : cfg.intf.addresses) {
			if(_is_ipv4_route(addr)) {
				ipv4_addrs.push_back(_get_addr(addr));
			} else {
				ipv6_addrs.push_back(_get_addr(addr));
			}
		}

		if(ipv4_addrs.size() > 0) {
			_write_table(firewall, cfg, ipv4_addrs, true, fwd_table);
			firewall << "\n";
		}

		if(ipv6_addrs.size() > 0) {
			_write_table(firewall, cfg, ipv6_addrs, false, fwd_table);
		}

		return firewall.str();
	}

	static std::string _gen_netdev_cfg(Config const & cfg, uint32_t fwd_table, std::filesystem::path const & private_keyfile,
			std::filesystem::path const & output_path, std::vector<SystemdFilespec> & symmetric_keyfiles) {
		std::stringstream netdev;

		netdev << "# Autogenerated by wg2nd\n";
		netdev << "[NetDev]\n";
		netdev << "Name = " << cfg.intf.name << "\n";
		netdev << "Kind = wireguard\n";
		netdev << "Description = " << cfg.intf.name << " - wireguard tunnel\n";
		netdev << "\n";

		netdev << "[WireGuard]\n";
		netdev << "PrivateKeyFile = " << private_keyfile.string() << "\n";

		if(cfg.intf.listen_port.has_value()) {
			netdev << "ListenPort = " << cfg.intf.listen_port.value() << "\n";
		}

		if(cfg.intf.should_create_routes and cfg.intf.table != 0) {
			netdev << "RouteTable = ";

			switch(cfg.intf.table) {
				case LOCAL_TABLE:
					netdev << "local";
					break;
				case MAIN_TABLE:
					netdev << "main";
					break;
				default:
					netdev << cfg.intf.table;
					break;
			}

			netdev << "\n";
		}

		if(cfg.intf.should_create_routes and cfg.has_default_route) {
			netdev << "FirewallMark = 0x" << std::hex << fwd_table << std::dec << "\n";
		}

		netdev << "\n";

		for(Peer const & peer : cfg.peers) {
			netdev << "[WireGuardPeer]\n";
			netdev << "PublicKey = " << peer.public_key << "\n";

			if(!peer.endpoint.empty()) {
				netdev << "Endpoint = " << peer.endpoint << "\n";
			}

			if(!peer.preshared_key.empty()) {
				std::string filename = public_keyfile_name(peer.public_key);

				symmetric_keyfiles.push_back(SystemdFilespec {
					.name = filename,
					.contents = peer.preshared_key + "\n",
				});

				netdev << "PresharedKeyFile = " << (output_path / filename).c_str() << "\n";
			}

			for(Cidr const & cidr : peer.allowed_ips) {
				netdev << "AllowedIPs = " << cidr.route << "\n";
			}

			if(!peer.persistent_keepalive.empty()) {
				netdev << "PersistentKeepalive = " << peer.persistent_keepalive << "\n";
			}

			netdev << "\n";
		}

		return netdev.str();
	}

	static std::string_view activation_policy_keyword(ActivationPolicy activation_policy) {
		switch(activation_policy) {
			case ActivationPolicy::MANUAL:
				return "manual";
			case ActivationPolicy::UP:
				return "up";
		}

		return "none";
	}

	static std::string _gen_network_cfg(Config const & cfg, uint32_t fwd_table, ActivationPolicy activation_policy) {
		std::stringstream network;

		network << "# Autogenerated by wg2nd\n";
		network << "[Match]\n";
		network << "Name = " << cfg.intf.name << "\n";
		network << "\n";

		network << "[Link]" << "\n";

		network << "ActivationPolicy = " << activation_policy_keyword(activation_policy) << "\n";

		if(!cfg.intf.mtu.empty()) {
			network << "MTUBytes = " << cfg.intf.mtu << "\n";
		}
		network << "\n";

		network << "[Network]\n";
		for(std::string const & addr : cfg.intf.addresses) {
			network << "Address = " << addr << "\n";
		}

		for(std::string const & dns : cfg.intf.DNS) {
			network << "DNS = " << dns << "\n";
		}

		if(cfg.has_default_route and cfg.intf.DNS.size() > 0) {
			network << "Domains = ~." << "\n";
		}

		network << "\n";

		if(!cfg.intf.should_create_routes) {
			return network.str();
		}

		constexpr uint8_t POLICY_ROUTE_NONE = 0;
		constexpr uint8_t POLICY_ROUTE_V4 = 1 << 0;
		constexpr uint8_t POLICY_ROUTE_V6 = 1 << 1;
		constexpr uint8_t POLICY_ROUTE_BOTH = POLICY_ROUTE_V4 | POLICY_ROUTE_V6;

		uint8_t policy_route = POLICY_ROUTE_NONE;

		for(Peer const & peer : cfg.peers) {
			for(Cidr const & cidr : peer.allowed_ips) {
				if(cidr.is_default_route) {
					policy_route |= cidr.is_ipv4 ? POLICY_ROUTE_V4 : POLICY_ROUTE_V6;
				}
				
				network << "[Route]\n";
				network << "Destination = " << cidr.route << "\n";
				uint32_t table = cfg.has_default_route ? fwd_table : cfg.intf.table;
				if(table) {
					network << "Table = " << table << "\n";
				}
				network << "\n";
			}
		}

		if(policy_route != POLICY_ROUTE_NONE) {

			char const * family = nullptr;

			switch(policy_route) {
				case POLICY_ROUTE_V4:
					family = "ipv6";
					break;
				case POLICY_ROUTE_V6:
					family = "ipv4";
					break;
				case POLICY_ROUTE_BOTH:
					family = "both";
					break;
			}

			network << "[RoutingPolicyRule]\n";
			network << "SuppressPrefixLength = 0\n";
			network << "Family = " << family << "\n";
			network << "Priority = 32764\n";
			network << "\n";

			network << "[RoutingPolicyRule]\n";
			network << "FirewallMark = 0x" << std::hex << fwd_table << std::dec << "\n";
			network << "InvertRule = true\n";
			network << "Table = " << fwd_table << "\n";
			network << "Family = " << family << "\n";
			network << "Priority = 32765\n";
			network << "\n";

		}

		return network.str();
	}

	static uint32_t _deterministic_random_table(std::string const & interface_name) {

		uint32_t table = 0;
		while(table == 0 or table == MAIN_TABLE or table == LOCAL_TABLE) {
			table = deterministic_fwmark(interface_name);
		}

		return table;
	}

	SystemdConfig gen_systemd_config(
		Config const & cfg,
		std::filesystem::path const & keyfile_or_output_path,
		std::optional<std::string> const & filename,
		ActivationPolicy activation_policy
	) {

		// If the table is explicitly specified with Table=<number>,
		// all routes are added to this table.
		//
		// If Table=auto and a default route exists, this
		// table is used by the default route to supersede
		// non-encrypted traffic traveling to /0 routes in the
		// main routing table by using suppress_prefix policy rules.
		// These routes match a fwmark which is identical to the
		// table name. All other routes are placed in the main routing
		// table.
		//
		// If Table=off, no routes are added.
		uint32_t fwd_table = _deterministic_random_table(cfg.intf.name);

		std::vector<SystemdFilespec> symmetric_keyfiles;

		std::filesystem::path keyfile_path;
		std::filesystem::path output_path;

		if(keyfile_or_output_path.has_filename()) {
			keyfile_path = keyfile_or_output_path;
			output_path = keyfile_or_output_path.parent_path();
		} else {
			std::string private_keyfile = private_keyfile_name(cfg.intf.private_key);
			keyfile_path = keyfile_or_output_path / private_keyfile;
			output_path = keyfile_or_output_path;
		}

		std::vector<std::string> warnings;

#define WarnOnIntfField(field_, field_name) \
if(!cfg.intf.field_.empty()) { \
	warnings.push_back("[Interface] section contains a field \"" field_name "\" which does not have a systemd-networkd analog, omitting"); \
}

		WarnOnIntfField(preup, "PreUp")
		WarnOnIntfField(postup, "PostUp")
		WarnOnIntfField(predown, "PreDown")
		WarnOnIntfField(postdown, "PostDown")
		WarnOnIntfField(save_config, "SaveConfig")

		if(!cfg.intf.preup.empty()) {
			warnings.push_back("[Interface] section contains a field \"PreUp\" which does not have a systemd-networkd analog");
		}

		std::string const & basename = filename.value_or(cfg.intf.name);

		return SystemdConfig {
			.netdev = {
				.name = basename + ".netdev",
				.contents = _gen_netdev_cfg(cfg, fwd_table, keyfile_path, output_path, symmetric_keyfiles),
			},
			.network = {
				.name = basename + ".network",
				.contents = _gen_network_cfg(cfg, fwd_table, activation_policy)
			},
			.private_keyfile = {
				.name = keyfile_path.filename(),
				.contents = cfg.intf.private_key + "\n",
			},
			.symmetric_keyfiles = std::move(symmetric_keyfiles),
			.warnings = std::move(warnings),
			.firewall = _gen_nftables_firewall(cfg, fwd_table),
		};
	}

	SystemdConfig wg2nd(std::string const & interface_name, std::istream & stream,
			std::filesystem::path const & keyfile_or_output_path,
			std::optional<std::string> const & filename,
			ActivationPolicy activation_policy) {
		return gen_systemd_config(
			parse_config(interface_name, stream),
			keyfile_or_output_path,
			filename,
			activation_policy
		);
	}

}
