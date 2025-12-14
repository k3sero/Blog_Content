import os
import hashlib
from PIL import Image
import io

encoded_dir = './encoded'

mapping = {
    '540620915f9b7fe6bcc53d4e85b4eb0fe3473256': '0', #Albondiga
    'f843f88fe2d0200aef55eb939d8aabf8a7fd11c6': '1', #Hotdog
    'ac73481e19947518cdfa7b62a05d58ebd6518ff1': '0',
    '1b40311b28f982f3af6f5a4bd82e606b70f532cb': '1',
    'cff95c6f924269b729706ef73f7a000eb938165a': '0',
    '01501234d9a8cd97671b10c7e2f0186f48653149': '0',
    '06f01941adf78610edf0ac75303bd4e58c89b36f': '0',
    '2732a2edfb09302ebebccf472737d434717ff5e7': '0',
    '6ab7093374e8cf814f22a90c4357c1974c2ccdef': '1',
    'd229c53d89dbb4a8f963d8b350afd93dbfb422eb': '1',
    'd347f02ddee3daee6fe11b873229c4a496a72a0c': '1',
    '73588143de7ee8151787c239a9b7dab65ea06518': '1',
    '01e3a42a75901498b80fdc49a93cdb1a621ba6de': '0',
    'a39fcce7eefd0f2fb93dbaeb3bc9d396b06a647a': '1',
    '127199c525299ae7dd77e93a9f18fd50757c4d8f': '0',
    '68807b2b9b83064ede68c4a6706063c1c25fdee7': '0',
    'be51ac99227869a8866ec0b95c1455942228c8d8': '1',
    'a5096f850f166b778753d266f563e7a242c2a9da': '1',
    'c23b41e36de527fb91895068761132bead2c9e67': '0',
    'dec49174230254862fefedc81e1de524292d79ea': '0',
    '0f9a069c946fd565822519d872c2c1c893fb6614': '1',
    '74ac3cf3cc57fbed8f78155276418b665691f8d9': '1',
    'ff75b178cd4d1387674749778c90ad40f737c11a': '1',
    '73371269c157e684585663a5b6b5842281173f0a': '1',
    '555d8fe786f8ce4ac2d451e768ced9a1bce9d030': '1',
    '0750c21d2b5eb7b76b43e3fb230f5448be3c9ba0': '0',
    '83107ff294c3112fdd8622d420e2fc75132473cd': '1',
    '113b42526456c0d93c9d130c02b04c71f4ed8838': '0',
    '4755ccbee28a9bce050e1e0f06bfadbb63f9a531': '0',
    'be5117b51dc2a001d9cf21940833d303fc27e80f': '1',
    '952c0fb5e8404e7b101d285d0e8aa6b6c171c38f': '0',
    '30f07985a1b0cf5c9cbde4a04f9690d7fa724238': '0'
}

bits = ''
for f in sorted(os.listdir(encoded_dir)):
    path = os.path.join(encoded_dir, f)
    # Abrimos y guardamos igual que encoder.py
    with Image.open(path) as img:
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=95)
        h = hashlib.sha1(buf.getvalue()).hexdigest()
    bits += mapping[h]

flag = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
print(flag)
