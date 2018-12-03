"""
The current scope of this file, is to intercept and split standard
output and standard error, and 
"""

import os
import sys
import time

from . import util


class LogSplitter:
    def __init__(self, original_output):
        self.original_output = original_output
        self.outputs = [ original_output ]
        
    def add_output(self, output):
        self.outputs.append(output)
        
    def write(self, data):
        for output in self.outputs:
            output.write(data)
            
    def writelines(self, lines):
        for line in lines:
            self.write(line)

    def flush(self):
        for output in self.outputs:
            output.flush()
    
    def close(self):
        for output in self.outputs:
            output.close()


class Logger:
    _instance = None
    
    # Singleton pattern.
    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = object.__new__(cls, *args, **kwargs)
        return cls._instance
        
    def __init__(self):    
        self._filename_prefix = time.strftime("%Y%m%d-%H%M%S")
        log_path = self.get_log_path()
        if not os.path.exists(log_path):
            os.makedirs(log_path)
        
    def get_run_filepath(self):
        """Get the per-application run file name used for logging."""
        return os.path.join(self.get_log_path(), self._filename_prefix +".log")
        
    def get_log_path(self):
        return os.path.join(util.user_dir(prefer_local=True), "logs")

    def enable_log_files(self):
        self._replacement_stdout = LogSplitter(sys.stdout)
        sys.stdout = self._replacement_stdout
        
        self._replacement_stderr = LogSplitter(sys.stderr)
        sys.stderr = self._replacement_stderr
        
        f = open(self.get_run_filepath(), "w+")
        self._replacement_stdout.add_output(f)
        self._replacement_stderr.add_output(f)
        
    def disable_log_files(self):
        if self._replacement_stdout:
            sys.stdout = self._replacement_stdout.original_output
            self._replacement_stdout = None
            
        if self._replacement_stderr:
            sys.stderr = self._replacement_stderr.original_output
            self._replacement_stderr = None
