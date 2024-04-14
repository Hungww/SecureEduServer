from flask import Flask,jsonify
from flask import request
import pandas as pd
import numpy as np
import tldextract   
from flask_cors import CORS, cross_origin
import Levenshtein as lev
app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'
import base64
import requests
import pickle

web_df = pd.read_csv('top10milliondomains.csv')
# print the first 5 rows of the dataframe
print(web_df.head())
#print the last 5 rows of the dataframe
print(web_df.tail())
urls= web_df['Domain'].tolist()




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

    elif is_missspell_domain(domain):
        return True



@app.get('/api/v1/url_check')
@cross_origin()
def url_check():
    target= request.args.get('target',default = '*', type = str)
    print("Target: ", target)
    


    res= fishing_check(target)
    api_url="https://www.virustotal.com/api/v3/urls/"
    url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")

    api_url+=url_id

    headers = {
    "accept": "application/json",
    "x-apikey": "cfa9ad074770816d32d2aa6e23c0260c031f70bdb2e500b58632e802832e981e"
}
    api_response = requests.get(api_url, headers=headers)
    api_response= api_response.json()
    print(api_response['data']['attributes']["total_votes"])
    total_votes= api_response['data']['attributes']["total_votes"]
    last_analysis_stats= api_response['data']['attributes']['last_analysis_stats']

    last_analysis_results= api_response['data']['attributes']['last_analysis_results']
    
   #in last_analysis_results, get all object such that the value of the key 'category' is 'malicious'
    malicious_results = [obj for obj in last_analysis_results.values() if obj['category'] == 'malicious']

    #in last_analysis_results, get all object such that the value of the key 'category' is 'suspicious'
    suspicious_results = [obj for obj in last_analysis_results.values() if obj['category'] == 'suspicious']

    #in last_analysis_results, get all object such that the value of the key 'category' is 'harmless'
    harmless_results = [obj for obj in last_analysis_results.values() if obj['category'] == 'harmless']

    #in last_analysis_results, get all object such that the value of the key 'category' is 'undetected'
    undetected_results = [obj for obj in last_analysis_results.values() if obj['category'] == 'undetected']

   
    categories = api_response['data']['attributes']['categories']
    print("Categories: ", categories)

    

    
    
    
    response = jsonify({"res": res,"total_votes": total_votes, "last_analysis_stats": last_analysis_stats, "malicious_results":malicious_results, "suspicious_results":suspicious_results, "harmless_results":harmless_results, "undetected_results":undetected_results,"la" "categories":categories})
    

    return response
# %%
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
import pickle

# %%
import base64

url_id = base64.urlsafe_b64encode("https://www.facebook.com".encode()).decode().strip("=")
print(url_id)

# %%
spam_df = pd.read_csv("spam.csv")
spam_df['spam']= spam_df['Category'].apply(lambda x: 1 if x=='spam' else 0)
spam_df

# %%
x_train, x_test, y_train, y_test = train_test_split(spam_df.Message, spam_df.spam, test_size=0.25)
x_train

# %%
cv=CountVectorizer()
x_train_count=cv.fit_transform(x_train.values)
x_train_count

# %%
model=MultinomialNB()
model.fit(x_train_count, y_train)

# %% [markdown]
# Test:

# %%
email_ham = "Which class are you in?"
email_ham_count = cv.transform([email_ham])
model.predict(email_ham_count)



# %%





@app.get('/')
def index():
    target= request.args.get('target',default = '*', type = str)
    print("Target: ", target)
    email_spam = target
    email_spam_count = cv.transform([email_spam])
    res =model.predict(email_spam_count)
    print("AAAAAAAAAAAAAa")
    print(res)

    
    
    return str(res[0])


@app.get('/test')
def test():
    return "Hello World"
   

if __name__ == '__main__':
    app.run(host="172.28.241.21")