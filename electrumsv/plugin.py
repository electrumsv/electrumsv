#!/usr/bin/env python
#
# Electrum - lightweight Bitcoin client
# Copyright (C) 2015 Thomas Voegtlin
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from collections import namedtuple
import importlib.util
import os
import pkgutil
import time

from . import plugins
from .app_state import app_state
from .devices import DeviceMgr
from .logs import logs
from .util import profiler, DaemonThread


logger = logs.get_logger("plugin")

plugin_loaders = {}
hook_names = set()
hooks = {}

HardwarePluginToScan = namedtuple("HardwarePluginToScan", 'name,description,plugin,exception')


class Plugins(DaemonThread):

    @profiler
    def __init__(self, gui_name):
        super().__init__('plugins')
        app_state.plugins = self
        self.setName('Plugins')
        self.pkgpath = os.path.dirname(plugins.__file__)
        self.config = app_state.config
        self.hw_wallets = {}
        self.plugins = {}
        self.gui_name = gui_name
        self.descriptions = {}
        self.device_manager = DeviceMgr(self.config)
        self.load_plugins()
        self.add_jobs(self.device_manager.thread_jobs())
        self.start()

    def load_plugins(self):
        for loader, name, ispkg in pkgutil.iter_modules([self.pkgpath]):
            full_name = f'electrumsv.plugins.{name}'
            spec = importlib.util.find_spec(full_name)
            if spec is None:  # pkgutil found it but importlib can't ?!
                raise Exception(f"Error pre-loading {full_name}: no spec")
            try:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            except Exception as e:
                raise Exception(f"Error pre-loading {full_name}: {repr(e)}") from e
            d = module.__dict__
            gui_good = self.gui_name in d.get('available_for', [])
            if not gui_good:
                continue
            details = d.get('registers_keystore')
            if details:
                self.register_keystore(name, gui_good, details)
            self.descriptions[name] = d
            if not d.get('requires_wallet_type') and self.config.get('use_' + name):
                try:
                    self.load_plugin(name)
                except Exception as e:
                    logger.exception("cannot initialize plugin %s", name)

    def get(self, name):
        return self.plugins.get(name)

    def count(self):
        return len(self.plugins)

    def load_plugin(self, name):
        if name in self.plugins:
            return self.plugins[name]
        full_name = f'electrumsv.plugins.{name}.{self.gui_name}'
        spec = importlib.util.find_spec(full_name)
        if spec is None:
            raise RuntimeError("%s implementation for %s plugin not found"
                               % (self.gui_name, name))
        try:
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            plugin = module.Plugin(self, self.config, name)
        except Exception as e:
            raise Exception(f"Error loading {name} plugin: {repr(e)}") from e
        self.add_jobs(plugin.thread_jobs())
        self.plugins[name] = plugin
        logger.debug("loaded %s", name)
        return plugin

    def close_plugin(self, plugin):
        self.remove_jobs(plugin.thread_jobs())

    def enable(self, name):
        self.config.set_key('use_' + name, True, True)
        p = self.get(name)
        if p:
            return p
        return self.load_plugin(name)

    def disable(self, name):
        self.config.set_key('use_' + name, False, True)
        p = self.get(name)
        if not p:
            return
        self.plugins.pop(name)
        p.close()
        logger.debug("closed %s", name)

    def is_available(self, name, w):
        d = self.descriptions.get(name)
        if not d:
            return False
        deps = d.get('requires', [])
        for dep, s in deps:
            try:
                __import__(dep)
            except ImportError as e:
                logger.debug('Plugin %s unavailable %r', name, e)
                return False
        requires = d.get('requires_wallet_type', [])
        return not requires or w.wallet_type in requires

    def get_hardware_support(self):
        out = []
        for name, (gui_good, details) in self.hw_wallets.items():
            if gui_good:
                try:
                    p = self.get_plugin(name)
                    if p.is_enabled():
                        out.append(HardwarePluginToScan(name=name,
                                                        description=details[2],
                                                        plugin=p,
                                                        exception=None))
                except Exception as e:
                    logger.exception("cannot load plugin for %s", name)
                    out.append(HardwarePluginToScan(name=name,
                                                    description=details[2],
                                                    plugin=None,
                                                    exception=e))
        return out

    def register_keystore(self, name, gui_good, details):
        from .keystore import register_keystore
        def dynamic_constructor(d):
            return self.get_plugin(name).keystore_class(d)
        if details[0] == 'hardware':
            self.hw_wallets[name] = (gui_good, details)
            logger.debug("registering hardware %s: %s", name, details)
            register_keystore(details[1], dynamic_constructor)

    def get_plugin(self, name):
        if not name in self.plugins:
            self.load_plugin(name)
        return self.plugins[name]

    def run(self):
        while self.is_running():
            time.sleep(0.1)
            self.run_jobs()
        self.on_stop()


def hook(func):
    hook_names.add(func.__name__)
    return func

def run_hook(name, *args):
    results = []
    f_list = hooks.get(name, [])
    for p, f in f_list:
        if p.is_enabled():
            try:
                r = f(*args)
            except Exception:
                logger.exception("Plugin error")
                r = False
            if r:
                results.append(r)

    if results:
        assert len(results) == 1, results
        return results[0]


class BasePlugin:
    def __init__(self, parent, config, name):
        self.parent = parent  # The plugins object
        self.name = name
        self.config = config
        self.wallet = None
        # add self to hooks
        for k in dir(self):
            if k in hook_names:
                l = hooks.get(k, [])
                l.append((self, getattr(self, k)))
                hooks[k] = l

    def __str__(self):
        return self.name

    def close(self):
        # remove self from hooks
        for k in dir(self):
            if k in hook_names:
                l = hooks.get(k, [])
                l.remove((self, getattr(self, k)))
                hooks[k] = l
        self.parent.close_plugin(self)
        self.on_close()

    def on_close(self):
        pass

    def thread_jobs(self):
        return []

    def is_enabled(self):
        return self.is_available() and self.config.get('use_' + self.name) is True

    def is_available(self):
        return True
