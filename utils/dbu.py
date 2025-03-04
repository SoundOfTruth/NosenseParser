import json
from bs4 import BeautifulSoup


def get_bdu():
    bdu_dict = {}

    with open('report.html', 'r', encoding="utf-8") as file:
        src = file.read()

    soup = BeautifulSoup(src, 'html.parser')
    bdu_table = soup.find('table', class_='vulnerabilitiesTbl')
    table_rows = bdu_table.find_all('tr')
    for row in table_rows:
        bdu_data = row.find(class_='bdu')
        bdu_td = ' '.join(str(bdu_data).split('<br/>'))
        row_desc = row.find(class_='desc')
        if bdu_td != 'None':
            data = BeautifulSoup(bdu_td, 'html.parser')
            bdu_str = data.text
            bdu_dict[bdu_str] = {
                'desc': row_desc.text
            }
    return bdu_dict


if __name__ == '__main__':
    dbu = get_bdu()
    with open('debug.json', 'w', encoding='utf-8') as data_fp:
        json.dump(dbu, data_fp, indent=2, ensure_ascii=False)

