from pathlib import Path
from enum import Enum
import subprocess
import sys

WG2ND_EXECUTABLE = "./wg2nd"
TEST_DIRECTORY = './test/example_config'
TESTS = [
    'wg0',
    'wg1', # same as wg0 except with \r\n
]

def die(*args, code: int = 1, **kwargs):
    print(*args, **kwargs, file=sys.stderr)
    sys.exit(code)

class Wg2ndFileType( Enum ):
    NETWORK = 'network'
    NETDEV = 'netdev'
    KEYFILE = 'keyfile'
    NFT = 'nft'

def wg2nd_generate(filetype: Wg2ndFileType, path: Path):

    try:
        result = subprocess.run([
            WG2ND_EXECUTABLE, 'generate', '-t', filetype.value, str(path)
        ], capture_output=True, check=True)
    except FileNotFoundError:
        die(f'Failed to find executable "{WG2ND_EXECUTABLE}"')
    except subprocess.CalledProcessError as e:
        die(f'Failed to generate config with wg2nd: {e}')

    return str(result.stdout, encoding='utf-8')

def read_config(path: str) -> str:

    with open(path, 'r') as f:
        return f.read()

for test in TESTS:

    test_directory = Path(TEST_DIRECTORY) / test

    wg_config = test_directory / f'{test}.conf'

    expected_netdev = read_config(test_directory / f'{test}.netdev')
    expected_network = read_config(test_directory / f'{test}.network')
    expected_nftables = read_config(test_directory / 'nftables.conf')

    network = wg2nd_generate(Wg2ndFileType.NETWORK, wg_config)
    netdev = wg2nd_generate(Wg2ndFileType.NETDEV, wg_config)
    nftables = wg2nd_generate(Wg2ndFileType.NFT, wg_config)

    print(f'testing {test}')

    assert network == expected_network
    assert netdev == expected_netdev
    assert nftables == expected_nftables

    print('pass')
