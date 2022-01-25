# To perform operations on dataset
import pandas as pd
import numpy as np

# Machine learning model
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

# Visualization
from sklearn import metrics

# importing required packages
import ipaddress
import re
from bs4 import BeautifulSoup
import whois
import urllib
import urllib.request
from urllib.parse import urlparse
import requests
from datetime import datetime
from flask import Flask, request
import favicon
import json
import socket
import tldextract
import html5lib
import validators
from dateutil.relativedelta import relativedelta

app = Flask(__name__)

# Domain of the URL (Domain)
def getDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.","")
    return domain


def GetIp(domain):
    try:
        Ip = socket.gethostbyname(domain)
        print(Ip)
        return 1
    except:
        return 0


# 1.Checks for IP address in URL (Have_IP)
def havingIP(url):
    try:
        ipaddress.ip_address(url)
        ip = -1
    except:
        ip = 1
    return ip


# 2.Finding the length of URL and categorizing (URL_Length)
def getLength(url):
    if len(url) < 54:
        length = 1
    else:
        if len(url) >= 54 and len(url)<= 75:
            length = 0
        else:
            length = -1

    return length


# listing shortening services
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"


# 3. Checking for Shortening Services in URL (Tiny_URL)
def tinyURL(url):
    match = re.search(shortening_services, url)
    if match:
        return -1
    else:
        return 1


# 4.Checks the presence of @ in URL (Have_At)
def haveAtSign(url):
    if "@" in url:
        at = -1
    else:
        at = 1
    return at


# 5.Checking for redirection '//' in the url (Redirection)
def redirection(url):
    pos = url.rfind('//')
    if pos > 6:
        if pos > 7:
            return -1
        else:
            return 1
    else:
        return 1


# 6.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return -1  # phishing
    else:
        return 1  # legitimate


# 7. Having_sub_domain
def subdomain(url):
    if url.count('.') == 1:
        return 1
    else:
        if url.count('.') == 2:
            return 0
        else:
            return -1


# 8. SSlfinal_State
listofissuers = ['GeoTrust, GoDaddy, Network Solutions, Thawte, Comodo, Doster, VeriSign, Google Trust Services LLC']

import urllib.request as Ureq
from urllib.parse import urlparse


def final_state(url):
    import ssl, socket
    hostname = urlparse(url).hostname
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            cert = s.getpeercert()
            subject = dict(x[0] for x in cert['subject'])
            issued_to = subject['commonName']
            issuer = dict(x[0] for x in cert['issuer'])
            issued_by = issuer['commonName']

            for issuers in listofissuers:
                if(issued_by == issuers):
                    print(issuer)
        return 1
    except:
        return -1


# 9. Domain Registration Length
def Registration_length(domain):
    response = whois.whois(domain)
    print(response)
    creationdate = response.creation_date
    expirationdate = response.expiration_date
    try:
        time_difference = relativedelta(expirationdate[0], creationdate[0]).years
        print(time_difference)
        if time_difference < 1:
            return -1
        else:
            return 1
    except:
        time_difference = relativedelta(expirationdate, creationdate).years
        print(time_difference)
        if time_difference < 1:
            return -1
        else:
            return 1


# 10. Favicon
def faviconfinder(url2):
    try:
        favIcon = favicon.get(url2)
        Icon = favIcon[0]
        print(Icon.url)
        IconDomain = getDomain(Icon.url)
        urldomain = getDomain(url2)
        if IconDomain == urldomain:
            return 1
        else:
            return -1
    except:
        return -1


# 11. port
listofports = [21, 22, 23, 80, 443, 445, 1433, 1521, 3306, 3309]
returnedlist = []
listforchecking = [0, 0, 0, 1, 1, 0, 0, 0, 0, 0]


def port(domain):
    try:
        hostip = socket.gethostbyname(domain)
        for ports in listofports:
            a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            location = (hostip, ports)
            result_of_check = a_socket.connect_ex(location)

            if result_of_check == 0:
                print("Port is open")
                a_socket.close()
                returnedlist.append(1)
            else:
                print("Port is not open")
                a_socket.close()
                returnedlist.append(0)

        if returnedlist == listforchecking:
            print(returnedlist)
            return 1
        else:
            print(returnedlist)
            return 0
    except:
        return -1


# 12. HTTPS_token
def httpDomain(url):
    domain = urlparse(url).netloc
    if 'https' in domain:
        return 1
    else:
        return 0


# 13. Request_URL
# 14. URL_of_Anchor
# 15. Links_in_tags
# 16. SFH


# 17. Submitting_to_email
def submittingtoemail(url):
    try:
       r = requests.get(url)
       htmlContent = r.content
       soup = BeautifulSoup(htmlContent, 'html.parser')
       anchors = soup.find_all('a')

       for link in anchors:
           print(link)
           if('mailto' in link.get('href')):
                return -1
       else:
           return 1
    except:
        return -1


# 18. Abnormal_URL
def abnormalurl(url):
    host_name = urlparse(url).hostname
    print(host_name)
    if validators.domain(host_name):
        return 0
    else:
        return 1


# 19.Checks the number of forwardings (Web_Forwards)
def forwarding(response):
    if response == "":
        return 1
    else:
        if len(response.history) <= 2:
            return 0
        else:
            return 1


# 20.Checks the effect of mouse over on status bar (Mouse_Over)
def mouseOver(response):
    if response == "":
        return 1
    else:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return 1
        else:
            return 0


# 21.Checks the status of the right click attribute (Right_Click)
def rightClick(response):
    if response == "":
        return 1
    else:
        if re.findall(r"event.button ?== ?2", response.text):
            return 0
        else:
            return 1

# 22. Pop Up window

# 23. IFrame Redirection (iFrame)
def iframe(response):
    if response == "":
        return 1
    else:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return 0
        else:
            return 1


# 24.Survival time of domain: The difference between termination time and creation time (Domain_Age)
def domainAge(domain_name):
    creation_date = domain_name.creation_date
    expiration_date = domain_name.expiration_date
    if (isinstance(creation_date, str) or isinstance(expiration_date, str)):
        try:
            creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            return 1
    if ((expiration_date is None) or (creation_date is None)):
        return 1
    elif ((type(expiration_date) is list) or (type(creation_date) is list)):
        return 1
    else:
        ageofdomain = abs((expiration_date - creation_date).days)
        if ((ageofdomain / 30) < 6):
            age = 1
        else:
            age = 0
    return age


# 25. DNS Record
def Dns_record(url):
    try:
        getpointedurl = socket.gethostbyname(url)
        if getpointedurl != '':
            return 1
        else:
            return -1
    except:
        return -1



# 26.Web traffic (Web_Traffic)
def web_traffic(url):
    try:
        # Filling the whitespaces in the URL if any
        url = urllib.parse.quote(url)
        rank = \
        BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        rank = int(rank)
    except TypeError:
        return 1
    if rank < 100000:
        return 1
    else:
        return 0


# 27. Page_Rank
# 28. Google_Index
# 29. Links_pointing_to_page
def Linkspointing(url):
    try:
        x = Ureq.urlopen(url)
        print("Total Size of the Web Page = ", len(x.read()), " Bytes")
        url_p = urlparse(url)
        domain = '{uri.scheme}://{uri.netloc}/'.format(uri=url_p)
        print(domain)
        resp = requests.get(url)
        soup = BeautifulSoup(resp.text, 'html.parser')
        r = 0
        for link in soup.find_all('a'):
            temp = link.get('href')
            if temp is not None and domain in temp:
                print(temp)
                r = r+1
        print("Total links pointing to same domain = ", r)
        if r == 0:
            return -1
        else:
            if r > 0 and r <= 2:
                return 0
            else:
                return 1
    except:
        return -1


# 39. Statistical_report
phishinglink = ['https://attyyejeje.weebly.com/', 'https://email.uki.co.il/b/qy/?7Zz.v9&QR4-bJZA', 'https://secure-bellsouth-email-verificaions-website1.yolasite.com/', 'http://atelierslion.com/dir/soma/order-soma-from-mexico.html', 'http://caixasmsdiretocef.com', 'https://jalpademendez.gob.mx/btcomsecre/loading.php', 'https://btopenreach-update-bill.com/?eyJkYXRhIjogImVvSm5kVFRYaXgvRmQ2QzZ6OEJyUk9NMlUyaC9rbENBL2hZemdRaXp6aUVOeWVtdWtHQlBrOEZXZzA3WVBtSVoiLCAiaXYiOiAiR2NmdGprNUJnZFUzTVd1OTZFYm5Kdz09In0=', 'https://cw94828.tmweb.ru/main/1/info.php', 'https://ahmed-s-school-5828.thinkific.com/', 'https://kyc-formeta.buzz/metamask/loading.php']


def stastical_report(url):
    for items in phishinglink:
        if url == items:
            return -1
    else:
        return 1


from selenium import webdriver

def popupwindow(url):
    driver = webdriver.Firefox()
    driver_info = driver.get(url)
    print(driver_info)

# MACHINE LEARNING
# Reading the files
df = pd.read_csv('E:\Files\Dataset.csv')

# print(df)
X = df.iloc[:, :-1]

y = df.iloc[:, -1]

Xtrain, Xtest, ytrain, ytest = train_test_split(X, y, random_state=10)

model = DecisionTreeClassifier()

model.fit(Xtrain.values, ytrain.values)

ypred = model.predict(Xtest.values)

print(ypred)
print(metrics.classification_report(ypred, ytest))

print("\n\nAccuracy Score:", metrics.accuracy_score(ytest, ypred).round(2) * 100, "%")

# @app.route('/')
def hello_world():
    return 'Hello World'

# @app.route('/url')
def call_regex(url):
    # websiteUrl = request.args.get('webUrl')
    websiteUrl = url
    global domain_name
    domain = getDomain(websiteUrl)
    Ip = GetIp(domain)
    if Ip == 0:
        print('The Website with this domain doesnt exist')
        return 0

    # state = final_state(websiteUrl)
    # print(state)
    # faviconcheck(websiteUrl)
    feature1 = havingIP(websiteUrl)
    feature2 = getLength(websiteUrl)
    feature3 = tinyURL(websiteUrl)
    feature4 = haveAtSign(websiteUrl)
    feature5 = redirection(websiteUrl)
    feature6 = prefixSuffix(websiteUrl)
    feature7 = subdomain(domain)
    feature8 = 1                                    # SSlfinal_State
    feature9 = Registration_length(domain)          # Domain_registeration_length
    feature10 = faviconfinder(websiteUrl)           # Favicon
    feature11 = port(domain)                        # Port
    feature12 = httpDomain(websiteUrl)              # HTTPS_token
    feature13 = 1                                   # Request_URL
    feature14 = 1                                   # URL_of_Anchor
    feature15 = 1                                   # Links_in_tags
    feature16 = 1                                   # SFH
    feature17 = submittingtoemail(url)              # Submitting_to_email
    feature18 = abnormalurl(websiteUrl)             # Abnormal_URL

    try:
        response = requests.get(websiteUrl)
    except:
        response = ""

    feature19 = forwarding(response)
    feature20 = mouseOver(response)
    feature21 = rightClick(response)
    feature22 = 0                                   # popUpWindow
    feature23 = iframe(response)

    dns = 1
    try:
        domain_name = whois.whois(urlparse(websiteUrl).netloc)
    except:
        dns = -1

    feature24 = (1 if dns == 1 else domainAge(domain_name))
    feature25 = dns                                  # DNSRecord
    feature26 = web_traffic(websiteUrl)
    feature27 = 1
    feature28 = 1
    feature29 = Linkspointing(url)
    feature30 = stastical_report(websiteUrl)

    featuretocheck = [feature1, feature2, feature3, feature4, feature5, feature6, feature7, feature8, feature9, feature10, feature11, feature12, feature13, feature14, feature15, feature16, feature17, feature18, feature19, feature20, feature21, feature22, feature23, feature24, feature25, feature26, feature27, feature28, feature29, feature30]

    print(featuretocheck)
    prediction = model.predict([featuretocheck])
    predstr = np.array_str(prediction)
    print(predstr)
    return predstr


call_regex(input())


# if __name__ == "__main__":
#     app.run(debug=False)