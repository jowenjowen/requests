import requests


def test_can_access_urllib3_attribute():
    requests.five_d.domain.Packages().urllib3()


def test_can_access_idna_attribute():
    requests.five_d.domain.Packages().idna()


def test_can_access_chardet_attribute():
    requests.five_d.domain.Packages().chardet()
