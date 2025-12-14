import os
import hashlib
from collections import defaultdict
from PIL import Image
import io

encoded_dir = './encoded'
hash_to_files = defaultdict(list)

for f in sorted(os.listdir(encoded_dir)):
    path = os.path.join(encoded_dir, f)
    with Image.open(path) as img:
        
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=95)  
        h = hashlib.sha1(buf.getvalue()).hexdigest()
        hash_to_files[h].append(f)

print("Hashes y sus archivos asociados:")
for h, files in hash_to_files.items():
    print(f"{h} → {len(files)} veces → {files[0]}") 