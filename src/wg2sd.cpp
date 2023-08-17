#include "wg2sd.hpp"

#include <exception>
#include <sstream>
#include <random>
#include <regex>

#include <argon2.h>

std::string hashed_keyfile_name(std::string const & priv_key) {
	constexpr uint8_t const SALT[] = {
		0x1, 0x6, 0x1, 0x5, 0x5, 0x8, 0x3, 0xd, 0x2, 0x7,
		0x5, 0xc, 0x8, 0x8, 0x7, 0x2, 0x7, 0xa, 0xf, 0x5,
		0xa, 0x6, 0xc, 0x5, 0xf, 0xe, 0x6, 0x7, 0xf, 0xd,
		0x1, 0x5
	};

	uint8_t const * key = reinterpret_cast<uint8_t const *>(priv_key.c_str());
	uint32_t keylen = priv_key.size();

	uint8_t t_cost = 2; // 2-pass computation
	uint32_t m_cost = 1 << 17; // 128 mebibytes memory
	uint32_t parallelism = 1; // single thread

	constexpr size_t HASHLEN = 32;

	uint8_t hash[HASHLEN];

	argon2i_hash_raw(t_cost, m_cost, parallelism, key, keylen, SALT, sizeof(SALT), hash, HASHLEN);

	constexpr char KEYFILE_EXT[] = ".keyfile";

	char filename[HASHLEN + sizeof(KEYFILE_EXT)];

	constexpr char const HEX[] = "0123456789abcdefghijklmnopqrstuv";

	for(size_t i = 0; i < HASHLEN; i++) {
		filename[i] = HEX[hash[i] & 0x1F];
	}

	// copy null terminator
	for(size_t i = 0; i < sizeof(KEYFILE_EXT); i++) {
		filename[HASHLEN + i] = KEYFILE_EXT[i];
	}

	return std::string { filename } ;
}


namespace wg2sd {

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
					if(line[i] != ' ' and line[i] != '\t') {
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

	static std::string _gen_netdev_cfg(Config const & cfg, uint32_t fwd_table, std::string const & private_keyfile,
			std::vector<SystemdFilespec> & symmetric_keyfiles, std::string const & output_path) {
		std::stringstream netdev;

		netdev << "# Autogenerated by wg2sd\n";
		netdev << "[NetDev]\n";
		netdev << "Name = " << cfg.intf.name << "\n";
		netdev << "Kind = wireguard\n";
		netdev << "Description = " << cfg.intf.name << " - wireguard tunnel\n";

		if(!cfg.intf.mtu.empty()) {
			netdev << "MTUBytes = " << cfg.intf.mtu << "\n";
		}

		netdev << "\n";

		netdev << "[WireGuard]\n";
		netdev << "PrivateKeyFile = " << output_path;

		if(output_path.back() != '/') {
			netdev << "/";
		}

		netdev << private_keyfile << "\n";

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
				std::string filename = hashed_keyfile_name(peer.preshared_key);

				symmetric_keyfiles.push_back(SystemdFilespec {
					.name = filename,
					.contents = peer.preshared_key + "\n",
				});

				netdev << "PresharedKeyFile = " << filename << "\n";
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

	static std::string _gen_network_cfg(Config const & cfg, uint32_t fwd_table) {
		std::stringstream network;

		network << "# Autogenerated by wg2sd\n";
		network << "[Match]\n";
		network << "Name = " << cfg.intf.name << "\n";
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

	static uint32_t _random_table() {
		std::random_device rd;
		std::mt19937 rng { rd() };

		uint32_t table = 0;
		while(table == 0 or table == MAIN_TABLE or table == LOCAL_TABLE) {
			table = rng() % UINT32_MAX;
		}

		return table;
	}

	SystemdConfig gen_systemd_config(Config const & cfg, std::string const & output_path) {

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
		uint32_t fwd_table = _random_table();

		std::vector<SystemdFilespec> symmetric_keyfiles;

		std::string private_keyfile = hashed_keyfile_name(cfg.intf.private_key);

		return SystemdConfig {
			.netdev = {
				.name = cfg.intf.name + ".netdev",
				.contents = _gen_netdev_cfg(cfg, fwd_table, private_keyfile, symmetric_keyfiles, output_path),
			},
			.network = {
				.name = cfg.intf.name + ".network",
				.contents = _gen_network_cfg(cfg, fwd_table)
			},
			.private_keyfile = {
				.name = private_keyfile,
				.contents = cfg.intf.private_key + "\n",
			},
			.symmetric_keyfiles = std::move(symmetric_keyfiles)
		};
	}

	SystemdConfig wg2sd(std::string const & interface_name, std::istream & stream, std::string const & output_path) {
		return gen_systemd_config(parse_config(interface_name, stream), output_path);
	}

}
