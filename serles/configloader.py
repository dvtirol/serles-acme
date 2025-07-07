import os
import importlib
import ipaddress
from configparser import ConfigParser

_config = None
_backend = None

def get_config():
    """
    Reads the configuration from the environment variable or the default path.

    Returns:
        (dict, object): A tuple of ``config``, ``backend``.
    """
    global _config, _backend

    if _config is None:
        _config, _backend = load_config_and_backend(
            os.environ.get("CONFIG", "/etc/serles/config.ini")
        )
    return _config, _backend


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
    except KeyError:
        raise ConfigError(
            "please define the backend class to use in [serles]backend="
        ) from None

    try:
        backendModule = importlib.import_module(mod, __name__)
    except ModuleNotFoundError as e:
        raise ConfigError("the backend class could not be loaded") from e

    clsname = cls or "Backend"
    if not hasattr(backendModule, clsname):
        raise ConfigError(
            f"backend does not define a {clsname} class (wrong module loaded?)"
        ) from None

    try:
        backend = getattr(backendModule, clsname)(cparser)
    except Exception as e:
        raise ConfigError("exception while initializing backend") from e

    if not hasattr(backend, "sign"):
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

    try:
        config["allowWildcards"] = cparser["serles"].getboolean("allowWildcards", fallback=False)
    except ValueError:
        raise ConfigError("[serles]allowWildcards= must be 'true' or 'false'") from None

    return config, backend
