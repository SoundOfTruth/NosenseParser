import pandas as pd


'''
    Перед использованием запустите main.py,
    дождитесь завершения выполнения программы,
    самостоятельно переведите файл table_3.xlsx с.м. readme.md,
    переименуйте полученный файл в ttranslated.xlsx
    и вложите его в корневую директорию
'''


def make_third_table():
    try:
        df = pd.read_excel('translated.xlsx')
        df['КАТЭК'] = df['КАТЭК'].str.replace('КАТЭК', 'CAPEC')
        df = df.rename(columns={
            'КАТЭК': 'CAPEC',
            'Название обработки': 'Название атаки',
            ' Название обработки': 'Название атаки'
            }
        )
        df.to_excel('tables/table_3_translated.xlsx')
    except FileNotFoundError as ex:
        print(ex)


if __name__ == '__main__':
    make_third_table()
