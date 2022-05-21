def pytest_addoption(parser):
    parser.addoption('--extended', action='store_true', default=False,
                     help='Test against all supported encoding types')


def resolve_encodings(option):
    from pymerkle.hashing import SUPPORTED_ENCODINGS

    if option.extended:
        return SUPPORTED_ENCODINGS

    return ['utf-8', 'utf-16', 'utf-32']


option = None

def pytest_configure(config):
    global option
    option = config.option
