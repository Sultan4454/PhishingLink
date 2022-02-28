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
from flask import Flask, request, jsonify
import validators
from dateutil.relativedelta import relativedelta
import ssl, socket
from tld import get_tld
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

Ipaddr = ''
havingIp = ''
Length = ''
shortning_service = ''
At_symbol = ''
redirectingg = ''
preffix_suffix = ''
having_subdomain = ''
ssl_finalstate = ''
registration_length = ''
faviconico = ''
Port = ''
https = ''
Sfh = ''
emailsubmission = ''
Abnormalurl = ''
forward = ''
mouseover = ''
rightclick = ''
popup = ''
Iframe = ''
agedomain = 'Couldn\'t get Age Domain'
dnsrec = ''
traffic = ''
Rank = ''
linkspointing = ''
Stats = ''

# Domain of the URL (Domain)
def getDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain


def getonlyDomain(url):
    domain = urlparse(url).netloc
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")

    domain = domain.replace("." + get_tld(domain, fix_protocol=True), "")
    return domain


def GetIp(domain):
    try:
        global Ipaddr
        Ip = socket.gethostbyname(domain)
        Ipaddr = Ip
        print(Ip)
        return 1
    except:
        return -1


def getscarpdata(url):
    r = requests.get(url)
    htmlContent = r.content
    soup = BeautifulSoup(htmlContent, 'html.parser')
    return soup


# 1.Checks for IP address in URL (Have_IP)
def havingIP(url):
    global havingIp
    try:
        ipaddress.ip_address(url)
        ip = -1
        havingIp = 'IP present'
        print('IP present')
    except:
        print('No IP in Url')
        ip = 1
        havingIp = 'No IP in Url'
    return ip


# 2.Finding the length of URL and categorizing (URL_Length)
def getLength(url):
    global Length
    if len(url) < 54:
        length = 1
        Length = 'Length of the url is ' + str(len(url)) + ' characters'
        print('Length of the url is ' + str(len(url)) + ' characters')
    else:
        if len(url) >= 54 and len(url) <= 75:
            length = 0
            Length = 'Length of the url is ' + str(len(url)) + ' characters'
            print('Length of the url is ' + str(len(url)) + ' characters')
        else:
            length = -1
            Length = 'Length of the url is ' + str(len(url)) + ' characters'
            print('Length of the url is ' + str(len(url)) + ' characters')

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
    global shortning_service
    match = re.search(shortening_services, url)
    if match:
        shortning_service = 'Shortening service used'
        print('Shortening service used')
        return -1
    else:
        shortning_service = 'No Shortening services used'
        print('No Shortening services used')
        return 1


# 4.Checks the presence of @ in URL (Have_At)
def haveAtSign(url):
    global At_symbol
    if "@" in url:
        at = -1
        print('@ present in Url')
        At_symbol = '@ present in Url'
    else:
        at = 1
        At_symbol = 'No @ present in Url'
        print('No @ present in Url')
    return at


# 5.Checking for redirection '//' in the url (Redirection)
def redirection(url):
    global redirectingg
    pos = url.rfind('//')
    if pos > 6:
        redirectingg = '// at position 6'
        print('// at position 6')
        if pos > 7:
            redirectingg = '// position is greater than 7'
            print('// at position 7')
            return -1
        else:
            redirectingg = '// position is greater than 7'
            print('// position is greater than 7')
            return 1
    else:
        redirectingg = '// at position 6'
        return 1


# 6.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)
def prefixSuffix(url):
    global preffix_suffix
    if '-' in urlparse(url).netloc:
        preffix_suffix = '- found in Url'
        print('- found in Url')
        return -1
    else:
        preffix_suffix = 'No - found in Url'
        print('No - found in Url')
        return 1


# 7. Having_sub_domain
def subdomain(url):
    global having_subdomain
    if url.count('.') == 1:
        having_subdomain = 'No sub-domain present in url'
        print('No sub-domain present in url')
        return 1
    else:
        if url.count('.') == 2:
            having_subdomain = '1 sub-domain present in url'
            print('1 sub-domain present in url')
            return 0
        else:
            having_subdomain = 'More than 1 sub-domain present in url'
            print('More than 1 sub-domain present in url')
            return -1


# 8. SSlfinal_State
listofissuers = ['GeoTrust', 'GoDaddy', 'Network Solutions', 'Thawte', 'Comodo', 'Doster', 'VeriSign', 'Let\'s Encrypt', 'R3', 'Go Daddy Secure Certificate Authority - G2', 'GTS CA 1C3']


def final_state(url):
    global ssl_finalstate
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
            if issuers == issued_by:
                ssl_finalstate = issued_by
                print('Issuer from list')
                return 1
        else:
            ssl_finalstate = 'The issuer is not a trusted one'
            print('The issuer is not from the list')
            return 0
    except:
        ssl_finalstate = 'Unable to get SSl Issuer name - final_state'
        print('Unable to get SSl Issuer name - final_state')
        return -1


# 9. Domain Registration Length
def Registration_length(domain):
    global registration_length
    try:
        response = whois.whois(domain)
        creationdate = response.creation_date
        expirationdate = response.expiration_date
        if type(creationdate) == list and type(expirationdate) == list:
            print('The domain of the website was bought on ' + str(creationdate[0]))
            print('The domain of the website will expire on ' + str(expirationdate[0]))
            time_difference = relativedelta(expirationdate[0], creationdate[0]).years
            registration_length = 'The Domain Registration Length is ' + str(time_difference) + ' years'
            print('The Domain Registration Length is ' + str(time_difference) + ' years')
            if time_difference <= 1:
                return -1
            else:
                return 1

        if type(creationdate) == list and type(expirationdate) != list:
            print('The domain of the website was bought on ' + str(creationdate[0]))
            print('The domain of the website will expire on ' + str(expirationdate))
            time_difference = relativedelta(expirationdate, creationdate[0]).years
            registration_length = 'The Domain Registration Length is ' + str(time_difference) + ' years'
            print('The Domain Registration Length is ' + str(time_difference) + ' years')
            if time_difference <= 1:
                return -1
            else:
                return 1

        if type(creationdate) != list and type(expirationdate) == list:
            print('The domain of the website was bought on ' + str(creationdate))
            print('The domain of the website will expire on ' + str(expirationdate[0]))
            time_difference = relativedelta(expirationdate[0], creationdate).years
            registration_length = 'The Domain Registration Length is ' + str(time_difference) + ' years'
            print('The Domain Registration Length is ' + str(time_difference) + ' years')
            if time_difference <= 1:
                return -1
            else:
                return 1

        if expirationdate != list and creationdate != list:
            print('The domain of the website was bought on ' + str(creationdate))
            print('The domain of the website will expire on ' + str(expirationdate))
            time_difference = relativedelta(expirationdate, creationdate).years
            registration_length = 'The Domain Registration Length is ' + str(time_difference) + ' years'
            print('The Domain Registration Length is ' + str(time_difference) + ' years')
            if time_difference <= 1:
                return -1
            else:
                return 1
    except:
        registration_length = 'Wasnt able to get the Domain Registration Length'
        print('Wasnt able to get the Domain Registration Length')
        return -1


# 10. Favicon
def faviconM(scrapeddata, domain):
    global faviconico
    soup = scrapeddata
    try:
        icon_link = None
        if soup.find('link', rel="icon"):
            icon_link = soup.find('link', rel="icon")
        else:
            if soup.find('link', rel="shortcut icon"):
                icon_link = soup.find('link', rel="shortcut icon")

        if icon_link is not None:
            icon_href = icon_link.get('href')
            icon_domain = getDomain(icon_href)

            if icon_domain == domain:
                faviconico = 'From the same Domain'
                return 1
            else:
                faviconico = 'Not from Domain'
                print('Not from Domain')
                return -1
        else:
            faviconico = 'Has no favicon'
            print('Has no favicon')
            return 1
    except:
        meta = soup.find('meta', itemprop='image')
        if meta is not None:
            mcontent = meta.get('content')
            if mcontent[0] == '/':
                faviconico = 'From the same Domain'
                return 1
        else:
            faviconico = 'Has no favicon'
            print('Has no favicon')
            return -1


# 11. port
listofports = (21, 22, 23, 80, 443, 445, 1433, 1521, 3306, 3309)
returnedlist = []
listforchecking = [0, 0, 0, 1, 1, 0, 0, 0, 0, 0]


def port(domain):
    global Port
    hostip = socket.gethostbyname(domain)
    try:
        for ports in listofports:
            a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            location = (hostip, ports)
            result_of_check = a_socket.connect_ex(location)

            if result_of_check == 0:
                print("Port " + str(ports) + " is open")
                returnedlist.append(1)
                a_socket.close()
            else:
                print("Port " + str(ports) + " is not open")
                returnedlist.append(0)
                a_socket.close()

        # print('This is a returned list' + str(returnedlist))
        if returnedlist == listforchecking:
            Port = 'The ports that are expected to be closed are closed'
            print('The ports that are expected to be closed are closed')
            return 1
        else:
            Port = 'The ports that are expected to be closed are open'
            print('The ports that are expected to be closed are open')
            return -1
    except:
        Port = 'Can\'t get the ports'
        return -1


# 12. HTTPS_token
def httpDomain(url):
    global https
    domain = urlparse(url).netloc
    if 'https' in domain:
        https = 'The website owner is tricking with Https token'
        print('The website owner is tricking with Https token')
        return -1
    else:
        https = 'The website owner is not tricking with Https token'
        print('The website owner is not tricking with Https token')
        return 1


# 13. Request_URL
def request_url(scrapeddata, domain):
    soup = scrapeddata
    Imgpercentage = 0.0
    embedpercentage = 0.0
    sourcepercentage = 0.0

    imgtags = soup.find_all('img')
    if len(imgtags) <= 0:
        Imgpercentage = 0.0

    if len(imgtags) > 0:
        imgcount = 0
        r = 0
        for imgtag in imgtags:
            imgcount += 1
            href = imgtag.get('src')
            if href is not None:
                tagdomain = getDomain(href)
                if tagdomain == domain:
                    print('Image tag has the source domain same as Url domain - request_url')
                else:
                    r = r + 1

        if r != 0:
            Imgpercentage = r / imgcount * 100
        else:
            Imgpercentage = 0.0

    embedtags = soup.find_all('embed')
    if len(embedtags) <= 0:
        embedpercentage = 0.0

    if len(embedtags) > 0:
        embedcount = 0
        s = 0
        for embed in embedtags:
            embedcount += 1
            src = embed.get('src')
            if src is not None:
                emtagdomain = getDomain(src)
                if emtagdomain == domain:
                    print('Embed tag has the source domain same as Url domain - request_url')
                else:
                    s = s + 1

        if s != 0:
            embedpercentage = s / embedcount * 100
        else:
            embedpercentage = 0.0

    sources = soup.find_all('source')
    if len(sources) <= 0:
        sourcepercentage = 0.0

    if len(sources) > 0:
        sourcescount = 0
        t = 0
        for source in sources:
            sourcescount += 1
            sourcesrc = source.get('srcset')
            if sourcesrc is not None:
                sourtagsource = getDomain(sourcesrc)
                if sourtagsource == domain:
                    print('Source tag has the source domain same as Url domain - request_url')
                else:
                    t = t + 1

        if t != 0:
            sourcepercentage = t / sourcescount * 100
        else:
            sourcepercentage = 0.0

    if (Imgpercentage + embedpercentage + sourcepercentage) > 0.0:
        final_percentage = (Imgpercentage + embedpercentage + sourcepercentage) * 100 / 300
        print('The percentage of link with outer domain is : ' + str(final_percentage))

        if final_percentage < 22.0:
            return 1
        else:
            if final_percentage >= 22.0 and final_percentage < 61.0:
                return 0
            else:
                return -1
    else:
        print('The percentage of link with outer domain is : 0.0 percentage')
        return 1


# 14. URL_of_Anchor
# If no anchors on website then what to pass (imp)
def url_of_anchor(scrappedata):
    soup = scrappedata
    anchor = soup.find_all('a')

    if anchor is not None:
            linkcount = 0
            voidlinkcount = 0
            for link in anchor:
                linkcount += 1
                href = link.get('href')
                if href is not None:
                    if ('javascript:void(0)' in link.get('href')):
                        print('javascript:void(0) anchor - url-of-anchor')
                        voidlinkcount += 1

            if voidlinkcount != 0:
                voidpercentage = voidlinkcount / linkcount * 100
            else:
                voidpercentage = 0.0

            count = 0
            hashlinkcount = 0
            for link in anchor:
                count += 1
                href = link.get('href')
                if href is not None:
                    if ('#' in link.get('href')):
                        print('#anchor - url-of-anchor')
                        hashlinkcount += 1

            if hashlinkcount != 0:
                hashpercentage = hashlinkcount / linkcount * 100
            else:
                hashpercentage = 0.0

            anchorcount = 0
            emptylinkcount = 0
            for link in anchor:
                anchorcount += 1
                if link.get('href') == '':
                    print('Blank link - url-of-anchor')
                    emptylinkcount += 1

            if emptylinkcount != 0:
                emptypercentage = emptylinkcount / anchorcount * 100
            else:
                emptypercentage = 0.0


            if (emptypercentage + hashpercentage + emptypercentage) > 0.0:
                final_percentage = (emptypercentage + hashpercentage + voidpercentage) / 300 * 100
                print('The final percentage of empty links is ' + str(final_percentage))
                if final_percentage < 31.0:
                    print(1)
                    return 1
                else:
                    if final_percentage >= 31.0 and final_percentage <= 67.0:
                        # print(0)
                        return 0
                    else:
                        # print(-1)
                        return -1
            else:
                print('The final percentage of empty links is 0.0 percentage - urlofanchor')
                return 1
    else:
        return -1


# 15. Links_in_tags
def links_in_tags(scrappeddata, domain):
    soup = scrappeddata

    meta = soup.find_all('meta')
    metaoutdomain = 0
    metatagcounts = 0
    for met in meta:
        mcontent = met.get('content')
        if mcontent is not None:
            if 'http' in mcontent:
                metadomain = getDomain(mcontent)
                metatagcounts += 1
                if metadomain == domain:
                    print('Meta tag has the content domain same as Url domain')
                else:
                    metaoutdomain += 1

    if metaoutdomain != 0:
        metapercentage = metaoutdomain / metatagcounts * 100
    else:
        metapercentage = 0.0

    scripts = soup.find_all('script')

    scriptsoutdomain = 0
    scripttagcounts = 0
    for script in scripts:
        scontent = script.get('src')
        if scontent is not None:
            if 'http' in scontent:
                scripttagcounts += 1
                scriptdomain = getDomain(scontent)
                if scriptdomain == domain:
                    print('Script tag has the source domain same as Url domain')
                else:
                    scriptsoutdomain += 1

    if scriptsoutdomain != 0:
        scriptpercentage = scriptsoutdomain / scripttagcounts * 100
    else:
        scriptpercentage = 0.0

    links = soup.find_all('link')

    linksoutdomain = 0
    linktagcounts = 0
    for link in links:
        lcontent = link.get('href')
        if lcontent is not None:
            if 'http' in lcontent:
                linktagcounts += 1
                scriptdomain = getDomain(lcontent)
                if scriptdomain == domain:
                    print('Link tag has the href domain same as Url domain')
                else:
                    linksoutdomain += 1

    if linksoutdomain != 0:
        linkpercentage = linksoutdomain / linktagcounts * 100
    else:
        linkpercentage = 0.0

    if (metapercentage + scriptpercentage + linkpercentage) > 0.0:
        final_percentage = (metapercentage + scriptpercentage + linkpercentage) * 100 / 300

        print('The percentage of link with outer domain is : ' + str(final_percentage))
        if final_percentage < 17.0:
            return 1
        else:
            if final_percentage >= 17.0 and final_percentage <= 81.0:
                return 0
            else:
                return -1
    else:
        print('The percentage of link with outer domain is : 0.0 percentage - linksintags')
        return 1


# 16. SFH
def sfh(scrappeddata, domain):
    global Sfh
    soup = scrappeddata

    formtag = soup.find_all('form')

    for form in formtag:
        if form.get('action') == 'about:blank' or form.get('action') == '':
            Sfh = 'Blank form action - sfh'
            print('Blank form action - sfh')
            return -1

        actionvalue = form.get('action')
        # print(actionvalue)
        if actionvalue is not None:
            if actionvalue[0] == '/':
                Sfh = 'Using the same domain for submitting form - sfh'
                print('Using the same domain for submitting form - sfh')
            else:
                actiondomain = getDomain(actionvalue)
                if actiondomain != domain:
                    Sfh = 'Form Submitting to different domain - sfh'
                    print('Form Submitting to different domain - sfh')
                    return 0
    else:
        Sfh = 'No perfect url found, all with /'
        print('No perfect url found, all with /')
        return 1


# 17. Submitting_to_email
def submittingtoemail(getsrapedata):
    global emailsubmission
    try:
        soup = getsrapedata
        anchors = soup.find_all('form')

        for link in anchors:
            if ('mailto' in link.get('action')):
                print('Mailto found in action of form - submittingtoemail')
                emailsubmission = 'Mailto found in action of form - submittingtoemail'
                return -1

        else:
            emailsubmission = 'Submitting to proper site'
            print('Submitting to proper site')
            return 1
    except:
        emailsubmission = 'Cant Find Submission of form'
        print('Cant Find Submission of form')
        return -1


# 18. Abnormal_URL
def abnormalurl(url):
    global Abnormalurl
    host_name = urlparse(url).hostname
    if validators.domain(host_name):
        Abnormalurl = 'Valid Host name'
        print('Valid Host name')
        return 1
    else:
        Abnormalurl = 'Invalid Host name'
        print('Invalid Host name')
        return -1


# 19.Checks the number of forwardings (Web_Forwards)
def forwarding(response):
    global forward
    if len(response.history) <= 1:
        forward = 'No Forwarding'
        print('No Forwarding')
        return 1
    else:
        if len(response.history) >= 2 and len(response.history) < 4:
            forward = 'No Forwarding'
            print('Forwarded Once')
            return 0
        else:
            forward = 'Forwarding more than Once'
            print('Forwarding more than Once')
            return -1


# 20.Checks the effect of mouse over on status bar (Mouse_Over)
def mouseOver(response):
    global mouseover
    if re.findall("<script>.+onmouseover.+</script>", response.text):
        mouseover = 'Mouseover used'
        print('Mouseover used')
        return -1
    else:
        mouseover = 'No Mouseover used'
        print('No mouseover used')
        return 1


# 21.Checks the status of the right click attribute (Right_Click)
def rightClick(response):
    global rightclick
    if re.findall(r"event.button ?== ?2", response.text):
        rightclick = 'Right Click is disabled'
        print('Right Click is disabled')
        return -1
    else:
        rightclick = 'Right Click is enabled'
        print('Right Click is enabled')
        return 1


# 22. Pop Up window
def popupwindow(scrappeddata):
    global popup
    soup = scrappeddata
    forms = soup.find_all('form')
    for form in forms:
        inputs = form.find_all('input')
        for input in inputs:
            inputtype = input.get('type')
            # print(inputtype)
            if inputtype != 'search':
                if inputtype != 'hidden':
                    if inputtype != 'submit':
                        if inputtype != 'email':
                            popup = 'Using other than search, hidden, submit, email'
                            print('Using other than search, hidden, submit, email')
                            return -1
                        else:
                            popup = 'Using from search, hidden, submit, email'
                            return 1
    else:
        popup = 'Using from search, hidden, submit, email'
        return 1


# 23. IFrame Redirection (iFrame)
def iframe(response):
    global Iframe
    if re.findall(r"[<iframe>|<frameBorder>]", response.text):
        Iframe = 'Not Using Iframe'
        print('Not Using Iframe')
        return 1
    else:
        Iframe = 'Iframe found'
        print('Iframe found')
        return -1


# 24.Survival time of domain: The difference between termination time and creation time (Domain_Age)
def domainEnd(domain_name):
    global agedomain
    expiration_date = domain_name.expiration_date
    if isinstance(expiration_date, str):
        try:
          expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except:
            print('Can\'t get the months left for the domain to expire')
            agedomain = 'Can\'t get the months left for the domain to expire'
            return -1

    if (expiration_date is None):
        print('Expiration date is None')
        return -1
    elif (type(expiration_date) is list):
        print('Expiration date is a list')
        return -1
    else:
        today = datetime.now()
        end = abs((expiration_date - today).days)
        monthstoend = end / 30
        if ((end/30) >= 6):
          end = 1
          print('The domain is live for' + str(monthstoend) + ' months')
          agedomain = 'The domain is live for ' + str(monthstoend) + ' months'
        else:
            print('The domain is live for ' + str(monthstoend) + ' months')
            agedomain = 'The domain is live for ' + str(monthstoend) + ' months'
            end = -1

    return end


# 25. DNS Record
def Dns_record(url):
    try:
        getpointedip = socket.gethostbyname(url)
        if getpointedip != '':
            return 1
        else:
            return -1
    except:
        return -1


# 26.Web traffic (Web_Traffic)
def web_traffic(url):
    global traffic
    try:
        # Filling the whitespaces in the URL if any
        url = urllib.parse.quote(url)
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        rank = int(rank)
    except TypeError:
        return 1
    if rank < 100000:
        traffic = 'Website Rank on Alexa top 10 Million is ' + str(rank)
        print('Website Rank on Alexa top 10 Million is ' + str(rank))
        return 1
    else:
        if rank > 100000:
            traffic = 'Website Rank on Alexa top 10 Million is ' + str(rank)
            print('Website Rank on Alexa top 10 Million is ' + str(rank))
            return 0
        else:
            traffic = 'Website Rank on Alexa top 10 Million is ' + str(rank)
            print('Website Rank on Alexa top 10 Million is ' + str(rank))
            return -1


# 27. Page_Rank
def Page_Rank(url):
    global Rank
    # get the API KEY here: https://developers.google.com/custom-search/v1/overview
    API_KEY = "AIzaSyAA3twKn6HsCNODRTknwct1-_mnCb63Rvk"
    # get your Search Engine ID on your CSE control panel
    SEARCH_ENGINE_ID = "d42c49816abae7b79"
    # target domain you want to track
    target_domain = urlparse(url).netloc
    # target keywords
    query = getonlyDomain(url)

    passed = 1.1
    for page in range(1, 11):
        passed -= 0.1
        print("[*] Going for page:", page)
        start = (page - 1) * 10 + 1
        url1 = f"https://www.googleapis.com/customsearch/v1?key={API_KEY}&cx={SEARCH_ENGINE_ID}&q={query}&start={start}"
        data = requests.get(url1).json()
        search_items = data.get("items")
        print(search_items)
        found = False
        if search_items is not None:
            for i, search_item in enumerate(search_items, start=1):
                title = search_item.get("title")
                snippet = search_item.get("snippet")
                html_snippet = search_item.get("htmlSnippet")
                link = search_item.get("link")
                firstdomain = urllib.parse.urlparse(link).netloc
                if firstdomain == target_domain:
                    rank = i + start - 1
                    print(f"[+] {target_domain} is found on rank #{rank} for keyword: '{query}'")
                    print("[+] Title:", title)
                    print("[+] Snippet:", snippet)
                    print("[+] URL:", link)

                    # target domain is found, exit out of the program
                    found = True
                    break

        if found:
            break

    Rank = str(passed)

    if passed < 0.2:
        return -1
    else:
        return 1


# 28. Google_Index
# We are checking Google Index Based on Page Rank

# 29. Links_pointing_to_page
def Linkspointing(scrapeddata, domain):
    global linkspointing
    soup = scrapeddata
    r = 0
    anchors = soup.find_all('a')
    if anchors is not None:
        for link in anchors:
            temp = link.get('href')
            if temp is not None and domain in temp:
                print(temp)
                r = r + 1

        linkspointing = "".join(["Total links pointing to same domain = ", str(r)])
        print("Total links pointing to same domain = ", r)
        if r == 0:
            return -1
        else:
            if r > 0 and r <= 2:
                return 0
            else:
                return 1
    else:
        return -1

# 30. Statistical_report
def stats_report(url, domain):
    global Stats
    r = requests.get(url)
    htmlContent = r.content
    soup = BeautifulSoup(htmlContent, 'html.parser')

    # print(soup)
    tds = soup.find_all('td', width="70%")
    # print(tds)
    if tds is not None:
        for td in tds:
                tdhref = td.string
                # print(tdhref)
                if tdhref is not None:
                    if domain in tdhref:
                        Stats = 'Phishing'
                        print('Phishing')
                        return -1
        else:
            Stats = 'Site Not present on Phishtank.org'
            print('Site Not present on Phishtank.org')
            return 1


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


@app.route('/')
def hello_world():
    return 'Hello World'


@app.route('/url')
def call_regex():
    websiteUrl = request.args.get('webUrl')
    # websiteUrl = url
    try:
        domain = getDomain(websiteUrl)
        ip = GetIp(domain)
        wp = ''
        pif = ''
        if ip == -1:
            print('The Website with this domain doesnt exist')
            wp = 'The Website with this domain doesnt exist'
            error = {
                'wp': wp
            }
            return jsonify(error)

        # stats = stats_report('https://phishtank.org', domain)
        # if stats == -1:
        #     pif = 'Website present on PhishTank.org'
        #     onphishtank = {
        #         'phishtank': pif
        #     }
        #     return jsonify(onphishtank)

        scrapedata = getscarpdata(websiteUrl)
        feature1 = havingIP(websiteUrl)
        feature2 = getLength(websiteUrl)
        feature3 = tinyURL(websiteUrl)
        feature4 = haveAtSign(websiteUrl)
        feature5 = redirection(websiteUrl)
        feature6 = prefixSuffix(websiteUrl)
        feature7 = subdomain(domain)
        feature8 = final_state(websiteUrl)              # SSlfinal_State
        feature9 = Registration_length(domain)          # Domain_registeration_length
        feature10 = faviconM(scrapedata, domain)        # Favicon
        feature11 = port(domain)                        # Port
        feature12 = httpDomain(websiteUrl)              # HTTPS_token
        feature13 = request_url(scrapedata, domain)     # Request_URL
        feature14 = url_of_anchor(scrapedata)           # URL_of_Anchor
        feature15 = links_in_tags(scrapedata, domain)   # Links_in_tags
        feature16 = sfh(scrapedata, domain)             # SFH
        feature17 = submittingtoemail(scrapedata)       # Submitting_to_email
        feature18 = abnormalurl(websiteUrl)             # Abnormal_URL

        try:
            response = requests.get(websiteUrl)
        except:
            response = ""

        if response == '':
            print('We got a bad request for the url passed, the website may be down please Try later')
            return 1

        feature19 = forwarding(response)
        feature20 = mouseOver(response)
        feature21 = rightClick(response)
        feature22 = popupwindow(scrapedata)             # popUpWindow
        feature23 = iframe(response)

        domain_present = 1
        try:
            domain_name = whois.whois(urlparse(websiteUrl).netloc)
        except:
            domain_present = -1

        feature24 = (-1 if domain_present == -1 else domainEnd(domain_name))  # DomainAge
        feature25 = 1  # DNSRecord
        feature26 = web_traffic(websiteUrl)
        feature27 = Page_Rank(websiteUrl)
        feature28 = 1 if feature27 != -1 else -1
        feature29 = Linkspointing(scrapedata, domain)
        feature30 = -1

        featuretocheck = [feature1, feature2, feature3, feature4, feature5, feature6, feature7, feature8, feature9,
                          feature10, feature11, feature12, feature13, feature14, feature15, feature16, feature17, feature18,
                          feature19, feature20, feature21, feature22, feature23, feature24, feature25, feature26, feature27,
                          feature28, feature29, feature30]

        print(featuretocheck)
        prediction = model.predict([featuretocheck])
        predstr = np.array_str(prediction)
        print(predstr)
        urldata = {
            'Url': websiteUrl,
            'Ipaddr': Ipaddr,
            'IP': havingIp,
            'Length': Length,
            'SS': shortning_service,
            'At': At_symbol,
            'Redirection': redirectingg,
            'Preffix_Suffix': preffix_suffix,
            'having_subdomain': having_subdomain,
            'ssl_finalstate': ssl_finalstate,
            'registration_length': registration_length,
            'faviconico': faviconico,
            'port': Port,
            'https': https,
            'Sfh': Sfh,
            'emailsubmission': emailsubmission,
            'abnormalurl': Abnormalurl,
            'forward': forward,
            'mouseover': mouseover,
            'rightclick': rightclick,
            'popup': popup,
            'Iframe': Iframe,
            'agedomain': agedomain,
            'dnsrec': 'Dns Record Present',
            'traffic': traffic,
            'Rank': Rank,
            'linkspointing': linkspointing,
            'Stats': Stats,
            'FinalResult': predstr,
            'Phish': 'Not a Phish' if prediction == 1 else 'Is a Phish'
        }
        # print(data)
        return jsonify(urldata)
    except:
        errordata = {
            'error': 'The website refused to connect'
        }
        return jsonify(errordata)

# call_regex(input('Enter the Url you wanna check :'))


if __name__ == "__main__":
    app.run()