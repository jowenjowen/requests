import requests


def test_can_access_urllib3_attribute():
    requests.doop.domain.Packages().urllib3()


def test_can_access_idna_attribute():
    requests.doop.domain.Packages().idna()


def test_can_access_chardet_attribute():
    requests.doop.domain.Packages().chardet()
