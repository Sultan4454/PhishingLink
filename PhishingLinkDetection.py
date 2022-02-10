def checkport(url):
    port = urlparse(url).port
    return port

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
        return 'The fav doesnt exist'

def faviconfinder(url2):
    try:
        favIcon = favicon.get(url2)
        Icon = favIcon[0]
        print(Icon.url)
        return 1
    except:
        return 0

def faviconcheck(url):
    # This the part of webscraping
    response = requests.get(url)
    html = response.content
    soup = BeautifulSoup(html, 'html.parser')
    favicon = soup.find_all('link')

    # print(favicon)
    for favs in favicon:
        print(favs)
        return favs

def fav3(url):
    page = urllib.urlopen(url)
    soup = BeautifulSoup(page)
    icon_link = soup.find("link", rel="shortcut icon")
    icon = urllib.urlopen(icon_link['href'])
    with open("test.ico", "wb") as f:
        f.write(icon.read())


# Python code for simple port scanning
def portgetter(url):
    try:
        host_ip = socket.gethostbyname('www.google.com')
    except socket.gaierror:

        # this means could not resolve the host
        print("there was an error resolving the host")
        sys.exit()
    for port in range(65535):  # check for all available ports
        global serv
        try:
            serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # create a new socket
            serv.bind((host_ip, port))  # bind socket with address
        except:
            print('[OPEN] Port open :', port)  # print open port number

        serv.close()  # close connection
        return serv





feature_names = ['having_IP_Address', 'URL_Length', 'Shortining_Service', 'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State', 'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL', 'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL', 'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe', 'age_of_domain', 'DNSRecord ', 'web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page', 'Statistical_report']


# Reading the files
df = pd.read_csv('E:\Files\Dataset.csv')

# print(df)

X = df.iloc[:, :-1]

y = df.iloc[:, -1]

Xtrain, Xtest, ytrain, ytest = train_test_split(X, y, random_state=10)

model = DecisionTreeClassifier()

model.fit(Xtrain.values, ytrain.values)

ypred = model.predict(Xtest.values)

print(metrics.classification_report(ypred, ytest))

print("\n\nAccuracy Score:", metrics.accuracy_score(ytest, ypred).round(2) * 100, "%")

# Flask Server

