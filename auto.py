import pickle
import os
import logging
import time
import base64
import hashlib
import datetime
import chromedriver_autoinstaller
from selenium import webdriver
from Cryptodome import Random
from Cryptodome.Cipher import AES

os.system("title 컬쳐랜드 핀번호 자동 충전기")

class AESCipher():
    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(AESCipher.str_to_bytes(key)).digest()

    @staticmethod
    def str_to_bytes(data):
        u_type = type(b''.decode('utf8'))
        if isinstance(data, u_type):
            return data.encode('utf8')
        return data

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * AESCipher.str_to_bytes(chr(self.bs - len(s) % self.bs))

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, raw):
        raw = self._pad(AESCipher.str_to_bytes(raw))
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw)).decode('utf-8')

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

class CultureLand():
    def __init__(self, ID, PW):
        self.ID = ID
        self.PW = PW
        self.PIN = list()
        os.system('cls')
        options = webdriver.ChromeOptions()
        options.add_experimental_option('excludeSwitches', ['enable-logging'])
        options.add_argument('headless')

        chrome_ver = chromedriver_autoinstaller.get_chrome_version().split('.')[0]
        try:
            self.driver = webdriver.Chrome(f'./{chrome_ver}/chromedriver.exe', options=options)
        except:
            chromedriver_autoinstaller.install(True)
            self.driver = webdriver.Chrome(f'./{chrome_ver}/chromedriver.exe', options=options)

        # self.driver = webdriver.Chrome("library/chromedriver.exe", options=options)


    # 로그인
    def Login(self):
        print("\n- 개발자: 펭귄\n\n")
        print("[!] 로그인 진행 중 ..\n")
        self.driver.get('https://m.cultureland.co.kr/mmb/loginMain.do')
        self.driver.find_element_by_id('txtUserId').send_keys(self.ID)
        self.driver.find_element_by_id('passwd').click()
        
        board = self.driver.find_element_by_id('mtk_passwd').find_elements_by_tag_name('img')

        # 특수문자 대체문자 불러오기
        with open('library/special.dict', 'rb') as FILE:
            special_replace = pickle.load(FILE)


        ALT = False # 대/소문자
        special_char = False # 특수문자

        for word in self.PW:
            if ALT:
                self.driver.find_element_by_id('mtk_cp').click()
                ALT = False
            elif special_char:
                self.driver.find_element_by_id('mtk_sp').click()
                special_char  = False
            if word.isupper() == True:
                self.driver.find_element_by_id('mtk_cp').click()
                ALT = True
            if word.isalnum() == False:
                self.driver.find_element_by_id('mtk_sp').click()
                word = special_replace[word]
                special_char = True
            for b in board:
                if word in b.get_attribute('alt'):
                    b.click()
                    break
        self.driver.find_element_by_id('mtk_done').click()
        self.driver.find_element_by_id('btnLogin').click()
        if self.driver.current_url != 'https://m.cultureland.co.kr/index.do': raise Exception
        else:
            os.system('cls')
            os.system('title [INFO] 컬쳐랜드 아이디: {0}'.format(key.decrypt(ID)))
            print("\n[+] 로그인 성공!")

    # 핀번호 입력받기
    def inputPIN(self):
        print('\n[!] 아래 핀번호를 입력하여 주세요. 한번에 최대 5개까지 충전이 가능하며, 아무것도 입력하지 않을 시 입력이 종료됩니다.\n\n')
        for i in range(5):
            P = input(f'[+] {i+1}번째 핀번호: ')
            if P == '': break
            else: self.PIN += [P]

    # 충전하기
    def Charge(self):
        self.driver.get('https://m.cultureland.co.kr/csh/cshGiftCard.do')
        self.PIN = [self.pinCheck(P) for P in self.PIN]
        puts = self.driver.find_element_by_class_name('content_box.charge').find_elements_by_tag_name('fieldset')
        for i, put in enumerate(puts):
            try:
                put = put.find_elements_by_tag_name('input')
                for j, num in enumerate(self.PIN[i]):
                    if j == 3:
                        put[j].click()
                        board = self.driver.find_elements_by_class_name('transkey_div.transkey_number2_div')
                        for b in board:
                            if 'display: block' in b.get_attribute('style'):
                                board = b
                        board = board.find_elements_by_tag_name('img')
                        for n in num:
                            for b in board:
                                if n in b.get_attribute('alt'):
                                    b.click()
                                    break
                    else: put[j].send_keys(num)
            except IndexError:
                self.driver.find_element_by_id('btnCshFrom').click()
                return 0
          
    def pinCheck(self, pin):
        new = str()
        for p in pin:
            if p.isdigit():
                new += p
                if len(new.replace(' ', '')) % 4 == 0 and len(new.replace(' ', '')) < 16: new += ' '
        return new.split(' ')

    def result(self):
        money = self.driver.find_element_by_class_name('charge_result')
        charge_krw = money.find_element_by_tag_name('dd').text
        money = money.find_element_by_class_name('tbl').find_element_by_tag_name('tbody').find_elements_by_tag_name('tr')
        os.system("cls")
        for m in money:
            m = m.text.split(' ')
            print("\n[!] 입력된 핀번호: {0}".format(m[1]))
            print("[!] 충전 결과: {0} {1}\n".format(m[2], m[3] if len(m[2:]) >= 2 else ''))
            print('-'*50)
        print(f"\n\n[+] 충전된 금액: {charge_krw}\n")
        now = time.localtime()
        self.driver.save_screenshot("충전내역/{0}년_{1}월{2}일_{3}시_{4}분_{5}초.png".format(now.tm_year, now.tm_mon,\
           now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec))

def EXIT(message):
    os.system('cls')
    input(message)
    exit()


key = AESCipher('암호화 키')

try:
    os.listdir("library").index('loginInfo.encrypt')
    with open("library/loginInfo.encrypt", "r") as FILE:
        ID, PW = FILE.readline().split('PENGUIN')
        print("\n[+] 로그인 정보를 불러왔습니다.\n\n")
except ValueError:
    print("\n[!] 입력한 컬쳐랜드 아이디/비밀번호는 컴퓨터에 암호화되어 저장됩니다.\n\n")
    ID = input("- 컬쳐랜드 아이디: ")
    PW = input("- 컬쳐랜드 비밀번호: ")
    with open("library/loginInfo.encrypt", "w") as FILE:
        FILE.write(key.encrypt(ID) + 'PENGUIN')
        FILE.write(key.encrypt(PW))
    EXIT("\n[-] 프로그램을 다시 실행하여 주세요.")

try:
    AUTO = CultureLand(key.decrypt(ID), key.decrypt(PW))
    AUTO.Login()
    AUTO.inputPIN()
except Exception as Error:
    os.remove('library/loginInfo.encrypt')
    AUTO.driver.quit()
    EXIT("\n[-] 로그인 실패. 다시 시도하여주세요.")
try:
    AUTO.Charge()
    AUTO.result()
    AUTO.driver.quit()
    input()
except Exception:
    AUTO.driver.quit()
    EXIT("\n[-] 핀번호 형식이 잘못되었습니다. 다시 시도하여 주세요.")