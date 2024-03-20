import zipfile
import requests
import os

class Analiser:
    def __init__(self, api_key):
        self.__API_KEY = api_key
        self.__base_url = "https://www.virustotal.com/api/v3"
        self.__base_headers = {
            "x-apikey": api_key
        }


    #MARK: - Puclic methods
        
    def analise_zip_with_one_file(self, path_to_zip: str, pass_zip):
        file_name_and_file = self._get_file_in_zip(path_to_zip, pass_zip)

        url_for_analize = self._get_url_for_analise_file(file_name_and_file)

        analisis = self._get_analisis(url_for_analize)

        text_esult_analisis = self._get_text_result_analisis(analisis)

        sha256 = analisis["meta"]["file_info"]["sha256"]
        behaviour_summary = self._get_behaviour_summary(sha256)

        text_behaviour_summary = self._get_text_result_behaviour_summary(behaviour_summary)

        return (text_esult_analisis, text_behaviour_summary)
    
    def create_text_file_resulr_analisis_zip_with_one_file(self, path_to_zip: str, pass_zip):
        tuple_text_result = self.analise_zip_with_one_file(path_to_zip, pass_zip)

        archive_name = os.path.splitext(os.path.basename(path_to_zip))[0]

        filename = f"result_analisis_{archive_name}.txt"
        with open(filename, "w") as file:
            file.write(tuple_text_result[0] + "\n\n" + tuple_text_result[1])


    # MARK: - Private methods
              
    def _get_file_in_zip(self, path_to_zip, pwd):
        password = pwd.encode()

        with zipfile.ZipFile(path_to_zip, 'r') as zip_ref:
            files = zip_ref.namelist()
            file_name = files[0]

            with zip_ref.open(file_name, pwd=password) as file:
                file_content = file.read()

        return (file_name, file_content)
            
    def _get_url_for_analise_file(self, file_name_and_file):
        url = self.__base_url + "/files"

        files = {"file": (file_name_and_file[0], file_name_and_file[1])}

        response = requests.post(url, headers=self.__base_headers, files=files)

        json = response.json()
        url = json["data"]["links"]["self"]
        return url
    
    def _get_analisis(self, url):
        headers = self.__base_headers
        headers["accept"] = "application/json"

        response = requests.get(url, headers=headers)
        return response.json()
    
    def _get_behaviour_summary(self, sha256):
        path = f"/files/{sha256}/behaviour_summary"
        url = self.__base_url + path

        headers = self.__base_headers
        headers["accept"] = "application/json"

        response = requests.get(url, headers=headers)
        return response.json()
    
    def _get_text_result_analisis(self, analisis):
        reult_text = "Результат анализа\n\n"
        reult_text += "Краткий итог\n\n"

        dict_stats = analisis["data"]["attributes"]["stats"]
        reult_text += "STATS:\n"

        for stat_name, stat_value in dict_stats.items():
            reult_text += f"{stat_name}: {stat_value}\n"


        dict_antivirus = analisis["data"]["attributes"]["results"]

        filtered_detected_dict = {k: v for k, v in dict_antivirus.items() if "result" in v and v["result"]}
        filtered_undetected_dict = {k: v for k, v in dict_antivirus.items() if v["result"] is None}

        reult_text += "\nАнтивирусы, которые обнаружили угрозу:\n"
        for antivirus in filtered_detected_dict.keys():
            reult_text += f"{antivirus}\n"

        reult_text += "\nАнтивирусы, которые НЕ обнаружили угрозу:\n"
        for antivirus in filtered_undetected_dict.keys():
            reult_text += f"{antivirus}\n"

        reult_text += "\nОбщая информация об антивирусах\n"

        for antivirus, info in dict_antivirus.items():
            engine_version = info["engine_version"]
            category = info["category"]
            result = info["result"]

            reult_text += f"\nАнтивирус: {antivirus}, {engine_version}\n"
            reult_text += f"category: {category}\n"
            reult_text += f"result: {result}\n"

        return reult_text

    def _get_text_result_behaviour_summary(self, json):
        text_behaviour_summary = "Краткая сводка поведения\n"

        behaviour_summary_data = json["data"]

        tags = behaviour_summary_data["tags"]
        text_behaviour_summary += "Основные теги\n"
        for tag in tags:
            text_behaviour_summary += f"{tag}\n"
        
        dns_lookups = behaviour_summary_data["dns_lookups"]
        text_behaviour_summary += "\nСписок доменов и IP-адресов, куда обращается файл"
        for dns_lookup in dns_lookups:
            hostname = dns_lookup["hostname"]
            resolved_ips = dns_lookup.get("resolved_ips", [])

            text_behaviour_summary += f"\n{hostname}\n"
            for resolved_ip in resolved_ips:
                text_behaviour_summary += f"{resolved_ip}\n"

        return text_behaviour_summary


api_key = "971d3cd0a709e28d7a7bbfd205ec41c93aa2db2be14972dd03952a46c7e818f7"

test_class = Analiser(api_key)
test_class.create_text_file_resulr_analisis_zip_with_one_file("protected_archive.zip", "netology")