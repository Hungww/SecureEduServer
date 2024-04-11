from flask import Flask,jsonify
from flask import request
import pandas as pd
import numpy as np
import tldextract   
import Levenshtein as lev
app = Flask(__name__)
web_df = pd.read_csv('top10milliondomains.csv')
import base64
import requests


#print the first 5 rows of the dataframe
print(web_df.head())
#print the last 5 rows of the dataframe
print(web_df.tail())
urls= web_df['Domain'].tolist()
scam_list=["w88one.vip"]
def get_domain(url):
    ext = tldextract.extract(url)
    print(ext)
    
    return ext

def is_missspell_domain(domain, threshold=0.9):
    max_similarity = 0
    max_url = ''
    for url in urls:
        similarity = lev.ratio(domain, url)
        if similarity > max_similarity:
            max_similarity = similarity
            max_url = url
        if similarity > threshold:
            return False
    print("Max similarity: ", max_similarity)
    print("Max url: ", max_url)
    return True

def fishing_check(target):
    test = get_domain(target)
    domain= test.domain
    suffix = test.suffix
    print(" Domain: ", domain)
    print(" Suffix: ", suffix)
    if f"{domain}.{suffix}" in urls:
        print("Domain is in the list of top 10 million domains")
        return False
    elif f"{domain}.{suffix}" in scam_list:
        print("Domain is in the list of scam domains")
        return True
    elif is_missspell_domain(domain):
        return True


@app.get('/api/v1/url_check')
def url_check():
    target= request.args.get('target',default = '*', type = str)
    print("Target: ", target)
    


    res= fishing_check(target)
    api_url="https://www.virustotal.com/api/v3/urls/"
    url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
    print("URL ID: ", url_id)
    api_url+=url_id
    print("API URL: ", api_url)
    headers = {
    "accept": "application/json",
    "x-apikey": "cfa9ad074770816d32d2aa6e23c0260c031f70bdb2e500b58632e802832e981e"
}
    api_response = requests.get(api_url, headers=headers)
    api_response= api_response.json()
    last_analysis_stats= api_response['data']['attributes']['last_analysis_stats']
    print("Last analysis stats: ", last_analysis_stats)
    last_analysis_results= api_response['data']['attributes']['last_analysis_results']
    
   #in last_analysis_results, get all object such that the value of the key 'category' is 'malicious'
    malicious_results = [obj for obj in last_analysis_results.values() if obj['category'] == 'malicious']
    print("Malicious results: ", malicious_results)
    #in last_analysis_results, get all object such that the value of the key 'category' is 'suspicious'
    suspicious_results = [obj for obj in last_analysis_results.values() if obj['category'] == 'suspicious']
    print("Suspicious results: ", suspicious_results)
    #in last_analysis_results, get all object such that the value of the key 'category' is 'harmless'
    harmless_results = [obj for obj in last_analysis_results.values() if obj['category'] == 'harmless']
    print("Harmless results: ", harmless_results)
    #in last_analysis_results, get all object such that the value of the key 'category' is 'undetected'
    undetected_results = [obj for obj in last_analysis_results.values() if obj['category'] == 'undetected']
    print("Undetected results: ", undetected_results)
    
    print("Last analysis results: ", last_analysis_results)
    categories = api_response['data']['attributes']['categories']
    print("Categories: ", categories)

    

    
    response= None
    if res:
        message="scam"
    else:
        message="ham"
    
    response = jsonify({"message": message, "last_analysis_stats": last_analysis_stats, "malicious_results":malicious_results, "suspicious_results":suspicious_results, "harmless_results":harmless_results, "undetected_results":undetected_results, "categories":categories})
    response.headers.add("Access-Control-Allow-Origin", "*")
    return response

@app.get('/')
def index():
    with open("expense.png", "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read())
    api_key="6a022360cf5d1c943e70eb6b03adf6a2"
    image= encoded_string
    url= "https://api.imgbb.com/1/upload"
    payload = {
    "key": api_key,
    "image": image
    }
    response = requests.post(url, payload)
    print(response.text)
    return "Hello, World!"
    

if __name__ == '__main__':
    app.run()