#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys
import shutil
import re

from tempfile import mkdtemp,mkstemp

from nfp_log import debug
from nfp_process import TimeoutCommand

#-----------------------------------------------------------------------
class CCoverResults:
  def __init__(self, bbs, exit_code):
    self.all_bbs=bbs
    self.all_unique_bbs=set(bbs)
    self.exit_code = int(exit_code)
    self.bbs = len(bbs) # Number of Basic Blocks executed
    self.unique_bbs = len(self.all_unique_bbs)

  def __repr__(self):
    return "Return code %d, Basic Block(s) %d, Unique(s) %d" % (self.exit_code, self.bbs, self.unique_bbs)

#-----------------------------------------------------------------------
class CDynRioCoverage:
  def __init__(self, path, arch):
    self.path = path
    self.arch = arch

  def read_coverage_log(self, logdir, maximum=1):
    bbs=[]
    matcher=re.compile("module\\[ *([0-9]+)\\]: 0x([0-9a-f]+), *[0-9]+")
    for filename in os.listdir(logdir):
      if filename.endswith(".log") and filename.startswith("drcov"):
        path = os.path.join(logdir, filename)
        with open(path, "rb") as f:
          for line in f.readlines():
            m=matcher.match(line)
            if m is not None:
              bbs.append((m.group(1),m.group(2)))
    return bbs

  def coverage(self, command, timeout=36000, hide_output = True):
    logdir = mkdtemp()
    cmdline = "%s/bin%s/drrun -t drcov -dump_text -logdir %s -- %s"
    if hide_output:
      cmdline += " >/dev/null 2>/dev/null"
    cmdline = cmdline % (self.path, self.arch, logdir, command)
    
    debug("Running command %s" % cmdline)
    cmd = TimeoutCommand(cmdline)
    ret = cmd.run(timeout)
    coverage = self.read_coverage_log(logdir)
    debug("Removing temporary directory %s " % logdir)
    shutil.rmtree(logdir)

    debug("Returning coverage data...")
    cover = CCoverResults(coverage, ret)
    return cover

  def multi_coverage(self, command, times, timeout=36000):
    ret = []
    debug("Performing coverage %d time(s)" % times)
    for i in range(times):
      ret.append(self.coverage(command, timeout))
    return ret

#-----------------------------------------------------------------------
class CPinCoverage:
  def __init__(self, path, arch):
    self.path = path
    self.arch = arch

  def read_coverage_log(self, logfile, maximum=1):
    edges = []
    with open(logfile, "rb") as f:
      lines = f.readlines()
      for line in lines:
        line_parts = line.split("\t")
        for i in xrange(0,int(line_parts[2])):
          edges.append((line_parts[0],line_parts[1]))
    return edges

  def coverage(self, command, timeout=36000, hide_output = True):
    tool_path = self.path+"/source/tools/RunTracer"
    if int(self.arch) == 32:
      tool_path = tool_path + "/obj-ia32/ccovtrace.so"
    elif int(self.arch) == 64:
      tool_path = tool_path + "/obj-intel64/ccovtrace.so"

    logfile = mkstemp()[1]
    # XXX: Do we want to use the .sh script? Using this we're limiting
    # ourselves to only Linux and MacOSX.
    cmdline = "%s/pin.sh -t %s -o %s -- %s"
    if hide_output:
      # ...although, when using "hide_output", we're already doing it...
      cmdline += " >/dev/null 2>/dev/null"
    cmdline = cmdline % (self.path, tool_path, logfile, command)
    
    debug("Running command %s" % cmdline)
    cmd = TimeoutCommand(cmdline)
    ret = cmd.run(timeout)
    coverage = self.read_coverage_log(logfile)
    debug("Removing temporary file %s " % logfile)
    os.remove(logfile)

    debug("Returning coverage data...")
    cover = CCoverResults(coverage, ret)
    return cover

  def multi_coverage(self, command, times, timeout=36000):
    ret = []
    debug("Performing coverage %d time(s)" % times)
    for i in range(times):
      ret.append(self.coverage(command, timeout))
    return ret

#-----------------------------------------------------------------------
BININST_AVAILABLE_TOOLS={"DynamoRIO":CDynRioCoverage,"Pin":CPinCoverage}

#-----------------------------------------------------------------------
def usage():
  print "Usage:", sys.argv[0], "program and arguments"

#-----------------------------------------------------------------------
def main(args):
  bininst_path = "/home/b/tools/DynamoRIO-Linux-4.2.0-3"
  arch = 64
  
  cmd_line = " ".join(args)
  cov_tool = CDynRioCoverage(bininst_path, arch)
  cov_data = cov_tool.coverage(cmd_line, 3600)
  print cov_data

  bininst_path = "/home/b/projects/domdodom/domdodom_fuzzer/pin"
  arch = 64

  cmd_line = " ".join(args)
  cov_tool = CPinCoverage(bininst_path, arch)
  cov_data = cov_tool.coverage(cmd_line, 3600)
  print cov_data


if __name__ == "__main__":
  if len(sys.argv) == 1:
    usage()
  else:
    main(sys.argv[1:])

