import requests
import json


def get_ip_info(ip_address):
    url = f"http://api.ipstack.com/{ip_address}?access_key=c679bf32199ed53ab4e664be0a90c412"

    response = requests.get(url)
    if response.status_code == 200:
        ip_info = response.json()
        return ip_info

    else:
        return 0, 0
