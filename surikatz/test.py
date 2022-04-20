from urllib.parse import urlparse

target = ['https://www.esiee.fr', 'http://wwwprd3.esiee.fr', 'https://37.187.158.103', '37.187.158.103:443' ]

for tg in target:
    if urlparse(tg).scheme == "https":
        print(tg)