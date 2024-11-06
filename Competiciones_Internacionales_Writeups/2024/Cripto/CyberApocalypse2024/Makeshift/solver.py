flag = "!?}De!e3d_5n_nipaOw_3eTR3bt4{_THB"
flag = flag[::-1]
plaintext = ''
 
for i in range(0, len(flag), 3):
    plaintext += flag[i+1]
    plaintext += flag[i+2]
    plaintext += flag[i]

print(plaintext)