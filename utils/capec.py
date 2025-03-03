
import requests
from bs4 import BeautifulSoup


def get_capec(cwe: str) -> dict | None:
    try:
        capec_dict = {}
        id = cwe.split('-')[-1]
        response = requests.get(
            f'https://cwe.mitre.org/data/definitions/{id}.html'
        )
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
        return capec_dict
    except Exception:
        if response.status_code != 200:
            print(response.status_code)
        return None


def get_capec_chance(cwe: str) -> dict:
    try:
        id = cwe.split('-')[-1]
        response = requests.get(
            f'https://capec.mitre.org/data/definitions/{id}.html'
        )
        soup = BeautifulSoup(response.text, 'html.parser')
        table = soup.find(attrs={'id': 'Likelihood_Of_Attack'})
        chance = table.find('p')
        return {
            'chance': f'CAPEC {chance.text}',
            'value': id
        }
    except Exception:
        return {
                'chance': 'No chance',
                'value': id
            }


if __name__ == '__main__':
    data = get_capec('CWE-78')
    capec_list = list(data['result']['dict'].keys())
    print(capec_list)
