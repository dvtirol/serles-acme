import os
import importlib
import ipaddress
from configparser import ConfigParser


def get_config():
    """
    Reads the configuration from the environment variable or the default path.

    Returns:
        (dict, class): A tuple of ``config``, ``backend``.
    """
    config, backend = load_config_and_backend(
        os.environ.get("CONFIG", "/etc/serles/config.ini")
    )
    return config, backend


class ConfigError(Exception):
    """
        This exception is raised when an error occurred while reading the
        config.
    """

    pass


def load_config_and_backend(filename):
    """
    Parses the config file given, or raises an exception. This is called
    directly on startup (as opposed to when a certificate request comes in) to
    alert the administrator to erros immediately.

    Args:
        filename: config file to load.

    Returns:
        (object, configparser.ConfigParser): A tuple containing the Backend
            class and the parsed config (dict-like)

    Raises:
        ConfigError: The config could not be loaded, is missing a required key
            or the specified Backend could not be loaded.
    """
    config = {}
    backend = None

    cparser = ConfigParser()
    if not cparser.read(filename):
        raise ConfigError("unable to load config file") from None

    try:
        mod, _, cls = cparser["serles"]["backend"].partition(":")
        backendModule = importlib.import_module(mod, __name__)
        backend = getattr(backendModule, cls or "Backend")(cparser)
        assert hasattr(backend, "sign")
    except KeyError:
        raise ConfigError(
            "please define the backend class to use in [serles]backend="
        ) from None
    except ModuleNotFoundError:
        raise ConfigError("the backend class could not be loaded") from None
    except AssertionError:
        raise ConfigError(
            "backend does not define a sign method (wrong class loaded?)"
        ) from None

    try:
        config["database"] = cparser["serles"]["database"]
    except KeyError:
        raise ConfigError("no [serles]database= configured") from None

    try:
        ranges = cparser["serles"]["allowedServerIpRanges"].splitlines()
        config["allowedServerIpRanges"] = [
            ipaddress.ip_network(cidr) for cidr in ranges if cidr
        ]
    except KeyError:
        config["allowedServerIpRanges"] = None  # if not defined, allow from everywhere.

    try:
        ranges = cparser["serles"]["excludeServerIpRanges"].splitlines()
        config["excludeServerIpRanges"] = [
            ipaddress.ip_network(cidr) for cidr in ranges if cidr
        ]
    except KeyError:
        config["excludeServerIpRanges"] = None

    try:
        config["subjectNameTemplate"] = cparser["serles"]["subjectNameTemplate"]
    except KeyError:
        raise ConfigError("must define [serles]subjectNameTemplate=") from None

    try:
        config["forceTemplateDN"] = cparser["serles"].getboolean(
            "forceTemplateDN", fallback=False
        )
    except ValueError:
        raise ConfigError(
            "[serles]forceTemplateDN= must be 'true' or 'false'"
        ) from None

    try:
        config["verifyPTR"] = cparser["serles"].getboolean("verifyPTR", fallback=False)
    except ValueError:
        raise ConfigError("[serles]verifyPTR= must be 'true' or 'false'") from None

    return config, backend
