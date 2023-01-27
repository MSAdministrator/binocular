"""The main entry point for this package."""
from typing import Dict

import docker

from .base import Base
from .configuration import ConfigurationManager
from .services.virustotal import VirusTotal


class Binocular(Base):
    """Named after the package and is consider the main entrypoint for this package.
    
    All commandline arguments will flow through this class. These will be defined as
    properties, methods and derived classes.
    """
    
    SUPPORTED_SERVICES = {
        "virustotal": VirusTotal
    }

    def __init__(self) -> None:
        """Main entry point, including pre-flight checks.
        
        We check to ensure Docker is installed before continuing.
        If it is not, we provide guidance and exit.
        """
        # First check for configuration file 
        Base.config_manager = ConfigurationManager()
        if not Base.config:
            self.get_config()
 
        # next we check for docker
        if not self._check_if_docker_is_installed():
            self.__logger.critical(
                "You must have Docker, Docker Desktop or some variant installed before continuing."
                "Before you can continue, you must have Docker installed. Visit https://docker.com"
                " for more information."
            )
        Base.docker_client = docker.from_env()

    def get_config(self) -> Dict[str, str]:
        """Returns the current configuration file values.

        Returns:
            Dict[str, str]: Returns a dictionary of keys and values.
        """
        Base.config = Base.config_manager._read_from_disk(path=Base.config_manager.config_path)
        return Base.config

    def update_config(self) -> Dict[str, str]:
        """Returns the updated config, once updated.

        Returns:
            Dict[str, str]: Returns a dictionary of keys and values.
        """
        Base.config_manager._save_to_disk(path=Base.config_manager.config_path, data=Base.config_manager._prompt())
        return self.get_config()

    def run(self, value: str) -> None:
        return_dict = {}
        iocs = self._get_ioc_type(value=value)
        config = self.get_config()
        for service in self.config["services"]:
            if self.SUPPORTED_SERVICES.get(service.get("name")):
                if service.get("supported_indicators"):
                    for indicator in service["supported_indicators"]:
                        self.__logger.debug(f"Checking indicator '{indicator}'.")
                        if indicator not in return_dict:
                            return_dict[indicator] = {}
                        if service["name"] not in return_dict[indicator]:
                            return_dict[indicator][service["name"]] = []
                        if iocs.get(indicator) and iocs[indicator]:
                            for value in iocs[indicator]:
                                return_dict[indicator][service["name"]].append(self.SUPPORTED_SERVICES[service["name"]](api_key=service["api_key"]).run(value))
                else:
                    self.__logger.info(f"The service '{service['name']}' does not have a configuration for 'supported_indicators'.")
            else:
                self.__logger.info(f"The service '{service['name']}' is not currently supported.")
        return return_dict
