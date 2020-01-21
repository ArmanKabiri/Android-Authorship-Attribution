# Author: Arman Kabiri
# Email: Arman.Kabiri94@gmail.com
# Date: Nov. 8, 2019

import pandas as pd
import koodous_customized
import os

# ### Constructing raw dataset from Koodous API
TOKEN = "0662592178d0f931c570aec3da2607cdcac2e421"
koodous_obj = koodous_customized.Koodous(TOKEN)

nApksRequest = 10000
json_filename = 'json_response%iAPKs.json' % nApksRequest
if not os.path.exists(json_filename):
    print("Getting list of APKs from Koodous:")
    json_response = koodous_obj.search('detected:True', nApksRequest)
    dataset = pd.DataFrame(json_response)
    dataset.to_json(json_filename)
else:
    print("Loading list of APKs from file:")
    dataset = pd.read_json(json_filename)

dataset.query("detected==True", inplace=True)
dataset.query("company!=''", inplace=True)
dataset.drop_duplicates('package_name', inplace=True)

dataset.info()

# ### Selecting developers
min_apps = 10
companies = dataset.groupby('company', axis=0)
companies = companies.size()[companies.size() > min_apps]
print(str(len(companies)) + ' companies, each containing at least %i apps, are selected:' % min_apps)
companies = list(companies.index)
print(companies)
dataset = dataset[dataset['company'].isin(companies)]

# ### Downloading APKs
print("Downloading APKs:")
os.chdir("./Malicious_Apks")
for company in companies:
    if not os.path.exists(company):
        os.makedirs(company)
    else:
        continue
    try:
        company_apps = dataset[dataset["company"] == company]
        app_hashs_list = company_apps['sha256'].values
        for app_hash in app_hashs_list:
            app_name = company_apps[company_apps['sha256'] == app_hash]['package_name'].values[0]
            koodous_obj.download_to_file(app_hash, '%s/%s.apk' % (company, app_name))
    except Exception as e:
        print(str(e))
        break

os.chdir("../")