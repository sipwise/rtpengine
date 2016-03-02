#!/usr/bin/env python
from __future__ import print_function
import subprocess
import sys
import unittest
import xmlrunner

def executeAndReturnOutput(command, env=None):
    p = subprocess.Popen(command, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env)
    stdoutdata, stderrdata = p.communicate()
    print(stderrdata, file=sys.stderr)
    return p.returncode, stdoutdata, stderrdata


class FakeCheck(unittest.TestCase):

    def compareFileResult(self, filename):
        res = executeAndReturnOutput(self.command)
        self.assertEquals(res[0], 0, res[2])
        with io.open(filename, 'r') as f:
            value = f.read()
        self.assertEquals(value, res[1])

    def compareResult(self, value):
        res = executeAndReturnOutput(self.command)
        self.assertEquals(res[0], 0, res[2])
        self.assertEquals(res[2], value)

    def execute(self):
        return executeAndReturnOutput(self.command, self.env)

    def setUp(self):
        self.env = {}
        self.command = ["true", ]

    def test_ok(self):
        res = self.execute()
        self.assertEquals(res[0], 0, res[2])

    def test_fail(self):
        self.command = ["false"]
        res = self.execute()
        self.assertEquals(res[0], 0, "failed!!")


if __name__ == '__main__':
    unittest.main(
        testRunner=xmlrunner.XMLTestRunner(output=sys.stdout),
        # these make sure that some options that are not applicable
        # remain hidden from the help menu.
        failfast=False, buffer=False, catchbreak=False)
