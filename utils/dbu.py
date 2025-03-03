from bs4 import BeautifulSoup


def get_bdu():
    bdu_dict = {}

    with open('report.html', 'r', encoding="utf-8") as file:
        src = file.read()

    soup = BeautifulSoup(src, 'html.parser')
    bdu_table = soup.find('table', class_='vulnerabilitiesTbl')
    table_rows = bdu_table.find_all('tr')
    for row in table_rows:
        row_bdu = row.find(class_='bdu')
        if row_bdu:
            row_desc = row.find(class_='desc')
            bdu_dict[row_bdu.text] = {
                'desc': row_desc.text
            }
    return bdu_dict


if __name__ == '__main__':
    print(get_bdu())
