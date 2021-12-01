# -*- encoding: utf-8

import sys

import pytest

from requests.domain import Help


def test_system_ssl():
    """Verify we're actually setting system_ssl when it should be available."""
    assert Help().info()['system_ssl']['version'] != ''


class VersionedPackage(object):
    def __init__(self, version):
        self.__version__ = version


def test_idna_without_version_attribute(mocker):
    """Older versions of IDNA don't provide a __version__ attribute, verify
    that if we have such a package, we don't blow up.
    """
    mocker.patch('requests.x.idna', new=None)
    assert Help().info()['idna'] == {'version': ''}


def test_idna_with_version_attribute(mocker):
    """Verify we're actually setting idna version when it should be available."""
    mocker.patch('requests.x.idna', new=VersionedPackage('2.6'))
    assert Help().info()['idna'] == {'version': '2.6'}
