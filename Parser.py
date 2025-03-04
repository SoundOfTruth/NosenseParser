import json
import pandas as pd

from utils.dbu import get_bdu
from utils.cwe import get_cwe
from utils.capec import get_capec, get_capec_chance
from utils.utils import time_of_function


class Parser:

    def __init__(self):
        self.data: dict = dict()
        self.cwe_set: set = set()
        self.cwe_capec: dict = dict()
        self.capec_data: dict = dict()

    @time_of_function
    def __get_report_data(self):
        self.data = get_bdu()  # read data from html file

    @time_of_function
    def __get_cwe(self):
        df = pd.read_excel('utils/vullist.xlsx')  # read data from xlsx file
        for bdu in self.data:
            cwe_list: list = get_cwe(df, bdu)
            dbu_payload = {
                'CWE': cwe_list,
            }
            self.data[bdu].update(dbu_payload)
            for cwe in cwe_list:
                self.cwe_set.add(cwe)  # get cwe unique values
        for obj in self.cwe_set:
            cwe_payload = {
                obj:
                {
                    'CAPEC High': [],
                    'CAPEC Medium': [],
                    'CAPEC Low': [],
                    'No chance': []
                }
            }
            self.cwe_capec.update(cwe_payload)

    @time_of_function
    def __get_cwe_capec(self):  # get cwe-capec dictionary
        for cwe in self.cwe_set:
            capec_data: dict | None = get_capec(cwe)
            if capec_data:
                self.capec_data.update(capec_data)  # data for table 3
                capec_list: list = list(capec_data.keys())
                for capec in capec_list:
                    capec_payload = get_capec_chance(capec)
                    self.cwe_capec[cwe][capec_payload['chance']].append(
                        capec_payload['value']
                    )

    @time_of_function
    def __group_data(self):
        for bdu in self.data:
            cwe_list: list = self.data[bdu].get('CWE')
            ch_set = set()
            cm_set = set()
            cl_set = set()
            nc_set = set()
            if cwe_list:
                for cwe in cwe_list:
                    payload = self.cwe_capec[cwe]
                    ch_set.update(set(payload['CAPEC High']))
                    cm_set.update(set(payload['CAPEC Medium']))
                    cl_set.update(set(payload['CAPEC Low']))
                    nc_set.update(set(payload['No chance']))
            self.data[bdu]['CAPEC High'] = list(ch_set)
            self.data[bdu]['CAPEC Medium'] = list(cm_set)
            self.data[bdu]['CAPEC Low'] = list(cl_set)
            self.data[bdu]['No chance'] = list(nc_set)


    @time_of_function
    def __get_tables(self):
        table_1_data = []
        table_2_data = []
        table_3_data = []
        for dbu in self.data:
            payload_1 = {}
            payload_2 = {}
            dbu_data = self.data[dbu]
            payload_1['DBU'] = dbu
            payload_1['CWE'] = ','.join(dbu_data['CWE'])
            payload_1['CAPEC High'] = ','.join(dbu_data['CAPEC High'])
            payload_1['CAPEC Medium'] = ','.join(dbu_data['CAPEC Medium'])
            payload_1['CAPEC Low'] = ','.join(dbu_data['CAPEC Low'])
            payload_1['No chance'] = ','.join(dbu_data['No chance'])
            payload_2['DBU'] = dbu
            payload_2['Наименование уязвимости'] = dbu_data['desc']
            table_1_data.append(payload_1)
            table_2_data.append(payload_2)

        for capec in self.capec_data:
            payload_3 = {
                'CAPEC': capec,
                'Наименование атаки': self.capec_data[capec]
            }
            table_3_data.append(payload_3)

        df_1 = pd.DataFrame(table_1_data)
        df_2 = pd.DataFrame(table_2_data)
        df_3 = pd.DataFrame(table_3_data)
        df_1.to_excel("tables/table_1.xlsx")
        df_2.to_excel("tables/table_2.xlsx")
        df_3.to_excel("tables/table_3.xlsx")

        with open('json/table_1.json', 'w', encoding='utf-8') as data_fp:
            json.dump(table_1_data, data_fp, indent=2, ensure_ascii=False)
        with open('json/table_2.json', 'w', encoding='utf-8') as data_fp:
            json.dump(table_2_data, data_fp, indent=2, ensure_ascii=False)
        with open('json/table_3.json', 'w', encoding='utf-8') as data_fp:
            json.dump(table_3_data, data_fp, indent=2, ensure_ascii=False)

    @time_of_function
    def start(self):
        self.__get_report_data()
        self.__get_cwe()
        self.__get_cwe_capec()
        self.__group_data()
        self.__get_tables()


if __name__ == '__main__':
    parser = Parser()
    print('runned')
    parser.start()
