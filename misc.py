#!/usr/bin/env python
# encoding: utf-8

import ConfigParser


def loadconfig():
    settings = ConfigParser.ConfigParser()
    settings.read('./config.txt')
    return settings
