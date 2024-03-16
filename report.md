# Краткий Итог
---
## 1. Сканирование zip архива

Код - [example_1.py](example_1.py)  
Файл с отчетом, который появляется в результате работы программы - [result_analisis_protected_archive.txt](result_analisis_protected_archive.txt)

### Обнаруженные угрозы

Количество антивирусов, пометивших файл как вредоносный: **25 шт.**  
- Lionic  
- ClamAV  
- FireEye  
- Symantec  
- ESET-NOD32  
- Avast  
- Kaspersky  
- BitDefender  
- DrWeb  
- VIPRE  
- Emsisoft  
- Ikarus  
- GData  
- Varist  
- Kingsoft  
- Arcabit  
- ViRobot  
- ZoneAlarm  
- Microsoft  
- Google  
- ALYac  
- Tencent  
- MAX  
- Fortinet  
- AVG  

### Не обнаружили угрозы

Количество антивирусов, не обнаруживших угрозу: **34 шт.**  
- Bkav  
- CAT-QuickHeal  
- Skyhigh  
- McAfee  
- Malwarebytes  
- Zillya  
- Sangfor  
- K7AntiVirus  
- K7GW  
- BitDefenderTheta  
- VirIT  
- TrendMicro-HouseCall  
- Cynet  
- NANO-Antivirus  
- SUPERAntiSpyware  
- MicroWorld-eScan  
- Rising  
- Sophos  
- Baidu  
- F-Secure  
- TrendMicro  
- CMC  
- Jiangmin  
- Avira  
- Antiy-AVL  
- Gridinsoft  
- Xcitium  
- AhnLab-V3  
- Acronis  
- VBA32  
- TACHYON  
- Zoner  
- Yandex  
- MaxSecure  
- Panda  
- Avast-Mobile  
- SymantecMobileInsight  
- BitDefenderFalx  
- tehtris  
- Elastic  
- APEX  
- Paloalto  
- Trapmine  
- Alibaba  
- Webroot  
- Cylance  
- SentinelOne  
- Trustlook  
- Cybereason  
- DeepInstinct  
- CrowdStrike  
- alibabacloud

  
### Сбои в работе

Количество антивирусов, в работе которых произошел сбой: **1 шт.**  
Количество антивирусов, не поддерживающих тип файла: **16 шт.**

---
## 1.2. Дополнительное задание, анализ поведения

Для итогового отчета о поведении файла необходим анализ данных, предоставляемых API.  
В [коде, на строке 124](example_1.py#L124) присутствует словарь `behaviour_summary_data` с данными об отчете.

По ключам, которые есть в json, можно получить информацию, например, об открытых процессах и так далее.  
По хорошему, предоставлять в виде отчета, как раз получаемый json.  
В своей работе я принял решение использовать только данные по двум ключам `tags` и `dns_lookups`.

#### Основные теги:
- DETECT_DEBUG_ENVIRONMENT
- LONG_SLEEPS

#### Список доменов и IP-адресов, куда обращается файл

- fp2e7a.wpc.phicdn.net  
  192.229.211.108
  
- fp2e7a.wpc.2be4.phicdn.net

---
## 2. Поиск и анализ уязвимостей в ПО

Код - [example_2.py](example_2.py)  
Файл с отчетом, который появляется в результате работы программы - [result_for_list_software.txt](result_for_list_software.txt)

### Найдены уязвимости в

- nginx 1.14.0  
- Apache HTTP Server 2.4.29  
- Wireshark 2.6.1  
- Google Chrome 68.0.3440.106  
- Mozilla Firefox 61.0.1

### Уязвимости не найдены в

- LibreOffice 6.0.7  
- 7zip 18.05  
- Adobe Reader 2018.011.20035  
- DjVu Reader 2.0.0.27  
- Notepad++ 7.5.6  


### Подробный отчет

Подробный отчет находится в файле [result_for_list_software.txt]().  
(Пример, для `nginx`) 

nginx v. 1.14.0  

найдено **2 CVE**.

#### CVE-2018-16843

- **Ссылка**: https://www.prio-n.com/kb/vulnerability/CVE-2018-16843
- **Описание**: nginx before versions 1.15.6 and 1.14.1 has a vulnerability in the implementation of HTTP/2 that can allow for excessive memory consumption. This issue affects nginx compiled with the ngx_http_v2_module (not compiled by default) if the 'http2' option of the 'listen' directive is used in a configuration file.


#### CVE-2018-16844

- **Ссылка**: https://www.prio-n.com/kb/vulnerability/CVE-2018-16844
- **Описание**: nginx before versions 1.15.6 and 1.14.1 has a vulnerability in the implementation of HTTP/2 that can allow for excessive CPU usage. This issue affects nginx compiled with the ngx_http_v2_module (not compiled by default) if the 'http2' option of the 'listen' directive is used in a configuration file.

