import requests


def test_can_access_urllib3_attribute():
    requests.Packages().urllib3()


def test_can_access_idna_attribute():
    requests.Packages().idna()


def test_can_access_chardet_attribute():
    requests.Packages().chardet()
