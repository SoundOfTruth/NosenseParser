
import pandas


def get_cwe(df: pandas.DataFrame, bdu: str) -> list:
    cwe_set = set()
    try:
        bdu_list = bdu.split()
        for _bdu in bdu_list:
            value = df.loc[df['Идентификатор'] == _bdu]
            cwe = value['Тип ошибки CWE'].values[0]
            if not type(cwe) is float:
                cwe_str = ''.join(cwe.split(', '))
                cwe_set.add(cwe_str)
        return list(cwe_set)
    except Exception as ex:
        print(ex)
        print(cwe_set)


if __name__ == '__main__':
    df = pandas.read_excel('utils/vullist.xlsx')
    cwe = get_cwe(df, 'BDU:2015-00227')
    print(type(cwe))
    print(cwe)
