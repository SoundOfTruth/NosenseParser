
import requests
from bs4 import BeautifulSoup


def logging(response: requests.Response, cwe, url, filename):
    log = f'{response.status_code} {cwe} {url}'
    path = f'logs/{filename}'
    with open(path, 'a') as file:
        file.write(log + '\n')


def get_capec(cwe: str) -> dict | None:
    try:
        capec_dict = {}
        id = cwe.split('-')[-1]
        url = f'https://cwe.mitre.org/data/definitions/{id}.html'
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find(attrs={'id': 'Related_Attack_Patterns'})
        table = table.find('table')
        rows = table.find_all('tr')
        rows.pop(0)
        for row in rows:
            table_data = row.find_all('td')
            capec_id = table_data[0].text
            payload = {
                capec_id: table_data[1].text
            }
            capec_dict.update(payload)
        logging(response, cwe, url, 'log.txt')
        return capec_dict
    except AttributeError:
        logging(response, cwe, url, 'nochance.txt')
        return None
    except Exception as ex:
        with open('exc.txt', 'a') as file:
            file.write(ex + '\n')
        return None


def get_capec_chance(cwe: str) -> dict:
    try:
        id = cwe.split('-')[-1]
        url = f'https://capec.mitre.org/data/definitions/{id}.html'
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find(attrs={'id': 'Likelihood_Of_Attack'})
        chance = table.find('p')
        logging(response, cwe, url, 'log.txt')
        return {
            'chance': f'CAPEC {chance.text}',
            'value': id
        }
    except AttributeError:
        logging(response, cwe, url, 'nochance.txt')
        return {
                'chance': 'No chance',
                'value': id
            }
    except Exception as ex:
        with open('exc.txt', 'a') as file:
            file.write(ex + '\n')
        return None
