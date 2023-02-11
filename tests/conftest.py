import itertools
from pymerkle.hashing import SUPPORTED_ALGORITHMS, SUPPORTED_ENCODINGS


def pytest_addoption(parser):
    parser.addoption('--extended', action='store_true', default=False,
                     help='Test against all supported encoding types')


def get_encodings(option):
    if option.extended:
        return SUPPORTED_ENCODINGS

    return ['utf-8', 'utf-16', 'utf-32']


def all_configs(option):
    combinations = []
    algorithms = SUPPORTED_ALGORITHMS
    encodings = get_encodings(option)

    for (security, algorithm, encoding) in itertools.product(
        (True, False),
        algorithms,
        encodings,
    ):
        yield {'security': security, 'algorithm': algorithm,
               'encoding': encoding}


option = None

def pytest_configure(config):
    global option
    option = config.option
