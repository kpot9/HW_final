import requests

class AnalizeSoftware:
    def __init__(self, api_key):
        self.__api_key = api_key
        self.__base_url = "https://vulners.com/api/v3/burp/softwareapi/"
        self.__base_headers = {"Content-Type": "application/json"}


    # MARK: - Public methods
        
    def create_text_result_for(self, list):
        detail_text_result = "\n\nПодробный отчет\n"
        results = []

        for software in list:
            name = software["Program"]
            version = software["Version"]
            json = self._request_for_one_software(name, version)
            result = self._get_text_result_for_one_software(name, version, json)
            results.append(result)


        filename = "result_for_list_software.txt"
        with open(filename, "w") as file:
            text = "Краткий итог анализа\n"


            found_vulnerability_count = 0
            not_found_vulnerability_count = 0

            found_vulnerability = "\n\nНайдены уязвимости в:"
            not_found_vulnerability = "\n\nУязвимости не найдены в:"

            for result in results:
                detail_text_result += result[2]

                name = result[0]
                if result[1] == True:
                    found_vulnerability_count += 1
                    found_vulnerability += f"\n{name}"

                elif result[1] == False:
                    not_found_vulnerability_count += 1
                    not_found_vulnerability += f"\n{name}"
                


            text += found_vulnerability + not_found_vulnerability

            file.write(text + detail_text_result)


    # MARK: - Private methods
            
    def _request_for_one_software(self, software_name, version):
        data = {
            "software": software_name,
            "version": version,
            "type": "software",
            "maxVulnerabilities": 100,
            "apiKey": self.__api_key
        }
        
        response = requests.post(self.__base_url, headers=self.__base_headers, json=data)
        return response.json()
    
    def _get_text_result_for_one_software(self, software_name, version, json):
        text_result = f"\n\nРезультат для {software_name} v. {version}"
        name_and_v = f"{software_name}" + f" {version}"

        cves = []
        exploits = {}

        json_data = json["data"]

        search = json_data.get("search")
        if search == None:
            text_result += "\nНе найдено"
            return (name_and_v, False, text_result)

        for value in json_data["search"]:
            new_cves = value["_source"]["cvelist"]
            cves.extend(new_cves)

            for cve in value["_source"]["cvelist"]:
                exploits[cve] = {
                    "href": value["_source"]["href"],
                    "description": value["_source"]["description"]
                }


        text_result += f"\nКол-во CVE: {len(cves)}"
        text_result += "\n\nСписок CVE:\n"
        for cve in cves:
            text_result += f"{cve}\n"

        text_result += "\nИнформация об эксплоитах для CVE:"
        for cve, info in exploits.items():
            text_result += f"\n{cve}:"
            text_result += f"\nСсылка: {info['href']}"
            text_result += f"\nОписание: {info['description']}\n"

        return (name_and_v, True, text_result)



software_list = [
    {"Program": "LibreOffice", "Version": "6.0.7"},
    {"Program": "7zip", "Version": "18.05"},
    {"Program": "Adobe Reader", "Version": "2018.011.20035"},
    {"Program": "nginx", "Version": "1.14.0"},
    {"Program": "Apache HTTP Server", "Version": "2.4.29"},
    {"Program": "DjVu Reader", "Version": "2.0.0.27"},
    {"Program": "Wireshark", "Version": "2.6.1"},
    {"Program": "Notepad++", "Version": "7.5.6"},
    {"Program": "Google Chrome", "Version": "68.0.3440.106"},
    {"Program": "Mozilla Firefox", "Version": "61.0.1"}
]
api_key = "FIBG4SEG3DQ0711CBQTJAQ3XIDHS92P29MLVBAZG10CVGK40SDZTHVOCE5BZNG4O"

test_class = AnalizeSoftware(api_key)
test_class.create_text_result_for(software_list)