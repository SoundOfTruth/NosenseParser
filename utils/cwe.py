
import pandas


def get_cwe(df: pandas.DataFrame, bdu: str) -> list:
    value = df.loc[df['Идентификатор'] == bdu]
    cwe = value['Тип ошибки CWE'].values[0]
    return cwe.split(', ')


if __name__ == '__main__':
    df = pandas.read_excel('utils/vullist.xlsx')
    cwe = get_cwe(df, 'BDU:2023-08343')
    print(type(cwe))
    print(cwe)
