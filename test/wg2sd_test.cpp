#include "utest.h"

#include "wg2sd.hpp"
#include <sstream>
#include <array>

namespace wg2sd {
	extern bool _is_default_route(std::string const & cidr);
	extern bool _is_ipv4_route(std::string const & cidr);
};

using namespace wg2sd;

UTEST(wg2sd, ip_helpers) {

	std::array<std::string, 8> default_routes = {
		"0/0",
		"0.0/0",
		"0.0.0/0",
		"0.0.0.0/0",
		"::/0",
		"::0/0",
		"::0/0",
		"0000:0000:0000:0000::/0",
	};

	for(std::string const & s : default_routes) {
		ASSERT_TRUE(_is_default_route(s));
	}

	std::array<std::string, 8> non_default_routes = {
		"192.168.0.1/24",
		"0.0.0.1/0",
		"0.0.0.0/32",
		"1/1",
		"2001:db8::1/64",
		"fe80::1/128",
		"::1/128",
		"2001:0db8:0000:0000::/64",
	};

	for(std::string const & s : non_default_routes) {
		ASSERT_FALSE(_is_default_route(s));
	}

	std::array<std::string, 4> ipv4_route = {
		"192.168.1.1",
		"0.0.0.0/0",
		"255.255.255.255/32",
		"1.2.3.4/0"
	};

	for(std::string const & s : ipv4_route) {
		ASSERT_TRUE(_is_ipv4_route(s));
	}

	std::array<std::string, 4> ipv6_route = {
		"2001:db8::1/64",
		"fe80::1/128",
		"::1/128",
		"2001:0db8:0000:0000::/64",
	};

	for(std::string const & s : ipv6_route) {
		ASSERT_FALSE(_is_ipv4_route(s));
	}
}

// Typical configuration, similar to that provided by mullvad.net
char const * CONFIG1 = (
	"[Interface]\n"
	"  # Device: Fast Mink\n"
	" PrivateKey = APmSX97Yww7WyHrQGG3u7oUJAKRazSyXVu9lD+A3aW8=\n"
	"Address = 10.14.123.142/32,fc00:aaaa:aaaa:aa01::6:ad78/128\n"
	"DNS =10.0.0.2\n"
	"[Peer]\n"
	"PublicKey = kMIIVxitU3/1AnAGwdL5KazDQ97MnkuEVz2sWihALnQ= \n"
	"AllowedIPs = 0.0.0.0/0,::0/0 # comment\n"
	"Endpoint = 194.36.25.33:51820\n"
);

// Configuration with multiple peers, interface peer tables are reversed
const char * CONFIG2 = (
	"[Peer]\n"
	"PublicKey = sMYYPASxJslAuszh5PgUPysrzZHHBOzawJ8PFbRQrHI=\n"
	"AllowedIPs = 192.168.1.2/32\n"
	"Endpoint = 203.0.113.1:51820\n"
	"\n"
	"[Peer]\n"
	"PublicKey = kB9CSPsPS5irR0ZpVAHZKPNHLQKjIFjmgc6MSCAiWUs=\n"
	"AllowedIPs = 192.168.1.3/32\n"
	"Endpoint = 203.0.113.2:51820\n"
	"\n"
	"[Interface]\n"
	"PrivateKey = ED3TF8deMhmXHa7Jrp024uv5T7jKl7611vFV3C1P+EY=\n"
	"Address = 192.168.1.1/24\n"
);

// Configuration with persistant keepalive, psk, and multiple DNS entries
const char * CONFIG3 = (
	"[Interface]\n"
	"PrivateKey = cJgeEfHUay0aKpV+k1lFK9nq9JJcqzKm8+Wh3EGtg1c=\n"
	"  Table=5\n"
	"\t\tAddress = 192.168.1.1/24\n"
	"DNS = 8.8.8.8,\t 8.8.4.4\n"
	"ListenPort = 4444\n"
	"Table = 42\n"
	"\n"
	"[Peer]\n"
	"   PublicKey = kB9CSPsPS5irR0ZpVAHZKPNHLQKjIFjmgc6MSCAiWUs=\n"
	"  AllowedIPs = 192.168.1.2/32\n"
	"Endpoint = 203.0.113.1:51820\n"
	"PersistentKeepalive = 25\n"
	"    PresharedKey = KIst3pK+YVHmM5k7NbNULKd2px9vaRsFi/y4E7NDWDQ=\n"
);

const char * INVALID_CONFIG = (
	"PrivateKey = kPvfTBQxgHpaXI9wVj6JrtYKIJLVXrf0zg6ON7qUxl8=\n"
	"Address = 192.168.1.1/24\n"
	"[Interface]\n"
);


UTEST(wg2sd, parses_config) {

	// CONFIG1
	std::istringstream ss { CONFIG1 };

	Config cfg = parse_config("wg", ss);

	ASSERT_STREQ(cfg.intf.name.c_str(), "wg");
	ASSERT_STREQ(cfg.intf.private_key.c_str(), "APmSX97Yww7WyHrQGG3u7oUJAKRazSyXVu9lD+A3aW8=");
	ASSERT_EQ(cfg.intf.table, 0ul);
	ASSERT_FALSE(cfg.intf.listen_port.has_value());
	ASSERT_EQ(cfg.intf.DNS.size(), 1ull);
	ASSERT_STREQ(cfg.intf.DNS.back().c_str(), "10.0.0.2");
	ASSERT_EQ(cfg.peers.size(), 1ull);

	const Peer & peer = cfg.peers[0];

	ASSERT_STREQ(peer.endpoint.c_str(), "194.36.25.33:51820");
	ASSERT_STREQ(peer.allowed_ips[0].route.c_str(), "0.0.0.0/0");
	ASSERT_TRUE(peer.allowed_ips[0].is_ipv4);
	ASSERT_TRUE(peer.allowed_ips[0].is_default_route);
	ASSERT_STREQ(peer.allowed_ips[1].route.c_str(), "::0/0");
	ASSERT_FALSE(peer.allowed_ips[1].is_ipv4);
	ASSERT_TRUE(peer.allowed_ips[1].is_default_route);

	ASSERT_STREQ(peer.public_key.c_str(), "kMIIVxitU3/1AnAGwdL5KazDQ97MnkuEVz2sWihALnQ=");
	ASSERT_STREQ(peer.preshared_key.c_str(), "");
	ASSERT_STREQ(peer.persistent_keepalive.c_str(), "");

	// CONFIG2
	std::istringstream ss2 { CONFIG2 };

	Config cfg2 = parse_config("wg", ss2);

	ASSERT_STREQ(cfg2.intf.name.c_str(), "wg");
	ASSERT_FALSE(cfg2.intf.listen_port.has_value());
	ASSERT_STREQ(cfg2.intf.private_key.c_str(), "ED3TF8deMhmXHa7Jrp024uv5T7jKl7611vFV3C1P+EY=");
	ASSERT_EQ(cfg2.intf.table, 0ul);
	ASSERT_EQ(cfg2.intf.DNS.size(), 0ull);
	
	ASSERT_EQ(cfg2.peers.size(), 2ull);

	const Peer &peer2_1 = cfg2.peers[0];

	ASSERT_STREQ(peer2_1.endpoint.c_str(), "203.0.113.1:51820");
	ASSERT_STREQ(peer2_1.allowed_ips[0].route.c_str(), "192.168.1.2/32");
	ASSERT_TRUE(peer2_1.allowed_ips[0].is_ipv4);
	ASSERT_FALSE(peer2_1.allowed_ips[0].is_default_route);
	ASSERT_STREQ(peer2_1.public_key.c_str(), "sMYYPASxJslAuszh5PgUPysrzZHHBOzawJ8PFbRQrHI=");
	ASSERT_STREQ(peer2_1.preshared_key.c_str(), "");
	ASSERT_STREQ(peer2_1.persistent_keepalive.c_str(), "");

	const Peer &peer2_2 = cfg2.peers[1];

	ASSERT_STREQ(peer2_2.endpoint.c_str(), "203.0.113.2:51820");
	ASSERT_STREQ(peer2_2.allowed_ips[0].route.c_str(), "192.168.1.3/32");
	ASSERT_TRUE(peer2_2.allowed_ips[0].is_ipv4);
	ASSERT_FALSE(peer2_2.allowed_ips[0].is_default_route);
	ASSERT_STREQ(peer2_2.public_key.c_str(), "kB9CSPsPS5irR0ZpVAHZKPNHLQKjIFjmgc6MSCAiWUs=");
	ASSERT_STREQ(peer2_2.preshared_key.c_str(), "");
	ASSERT_STREQ(peer2_2.persistent_keepalive.c_str(), "");

	// CONFIG3
	std::istringstream ss3 { CONFIG3 };

	Config cfg3 = parse_config("wg", ss3);

	ASSERT_STREQ(cfg3.intf.name.c_str(), "wg");
	ASSERT_STREQ(cfg3.intf.private_key.c_str(), "cJgeEfHUay0aKpV+k1lFK9nq9JJcqzKm8+Wh3EGtg1c=");
	ASSERT_EQ(cfg3.intf.table, 42ul);
	uint16_t port = cfg3.intf.listen_port.value();
	ASSERT_EQ(port, 4444);
	ASSERT_EQ(cfg3.intf.DNS.size(), 2ull);
	ASSERT_STREQ(cfg3.intf.DNS[0].c_str(), "8.8.8.8");
	ASSERT_STREQ(cfg3.intf.DNS[1].c_str(), "8.8.4.4");
	
	ASSERT_EQ(cfg3.peers.size(), 1ull);

	const Peer &peer3 = cfg3.peers[0];

	ASSERT_STREQ(peer3.endpoint.c_str(), "203.0.113.1:51820");
	ASSERT_STREQ(peer3.allowed_ips[0].route.c_str(), "192.168.1.2/32");
	ASSERT_TRUE(peer3.allowed_ips[0].is_ipv4);
	ASSERT_FALSE(peer3.allowed_ips[0].is_default_route);
	ASSERT_STREQ(peer3.public_key.c_str(), "kB9CSPsPS5irR0ZpVAHZKPNHLQKjIFjmgc6MSCAiWUs=");
	ASSERT_STREQ(peer3.preshared_key.c_str(), "KIst3pK+YVHmM5k7NbNULKd2px9vaRsFi/y4E7NDWDQ=");
	ASSERT_STREQ(peer3.persistent_keepalive.c_str(), "25");


	// INVALID_CONFIG
	std::istringstream ss4 { INVALID_CONFIG };

	ASSERT_EXCEPTION(parse_config("wg", ss4), ParsingException);
}

UTEST_MAIN()
