# -*- encoding: utf-8

from requests.doop.domain import Info


def test_system_ssl():
    """Verify we're actually setting system_ssl when it should be available."""
    assert Info().info()['system_ssl']['version'] != ''


class VersionedPackage:
    def __init__(self, version):
        self.__version__ = version


def test_idna_without_version_attribute(mocker):
    """Older versions of IDNA don't provide a __version__ attribute, verify
    that if we have such a package, we don't blow up.
    """
    mocker.patch('requests.doop.x.idna', new=None)
    assert Info().info()['idna'] == {'version': ''}


def test_idna_with_version_attribute(mocker):
    """Verify we're actually setting idna version when it should be available."""
    mocker.patch('requests.doop.x.idna', new=VersionedPackage('2.6'))
    assert Info().info()['idna'] == {'version': '2.6'}
