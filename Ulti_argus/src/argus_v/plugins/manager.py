import importlib
import os
import sys
import logging
from abc import ABC, abstractmethod

# Ensure src is in path to import siblings
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../")))

class ArgusPlugin(ABC):
    """
    Base class for all Argus features.
    """
    @abstractmethod
    def name(self):
        pass

    @abstractmethod
    def description(self):
        pass

    @abstractmethod
    def on_load(self):
        """Called when plugin is loaded"""
        pass

    def on_packet(self, flow_data):
        """Optional: Inspect raw packet data (called by Aegis Core)"""
        pass

    def on_payload(self, content):
        """Optional: Inspect decrypted payload (called by Aegis Proxy/Mnemosyne)"""
        pass

class PluginManager:
    def __init__(self, plugin_dir="d:/Argus_AI/src/argus_plugins"):
        self.plugin_dir = plugin_dir
        self.plugins = []
        self.stats = {} # Live activity tracking
        self.logger = logging.getLogger("PluginManager")

    def discover_and_load(self):
        self.logger.info(f"[*] Discovering plugins in {self.plugin_dir}...")
        sys.path.append(self.plugin_dir)
        
        if not os.path.exists(self.plugin_dir):
            os.makedirs(self.plugin_dir)
            return

        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py") and not filename.startswith("__") and filename != "manager.py":
                module_name = filename[:-3]
                try:
                    module = importlib.import_module(f"src.argus_plugins.{module_name}")
                    for attr_name in dir(module):
                        attr = getattr(module, attr_name)
                        if isinstance(attr, type) and issubclass(attr, ArgusPlugin) and attr is not ArgusPlugin:
                            plugin_instance = attr()
                            self.plugins.append(plugin_instance)
                            plugin_instance.on_load()
                            self.stats[plugin_instance.name()] = {"status": "active", "hits": 0, "health": 100}
                            self.logger.info(f"[+] Loaded Plugin: {plugin_instance.name()}")
                except Exception as e:
                    self.logger.error(f"[-] Failed to load {module_name}: {e}")

    def run_on_payload(self, content):
        results = {}
        for p in self.plugins:
            try:
                res = p.on_payload(content)
                if res:
                    results[p.name()] = res
                    self.stats[p.name()]["hits"] += 1
            except Exception as e:
                self.logger.error(f"Error in {p.name()}: {e}")
        return results

    def run_on_packet(self, flow_data):
        """Broadcast raw packet metadata to all plugins"""
        for p in self.plugins:
            try:
                p.on_packet(flow_data)
            except Exception as e:
                self.logger.error(f"Error in {p.name()} on_packet: {e}")

# Singleton
plugin_manager = PluginManager()
