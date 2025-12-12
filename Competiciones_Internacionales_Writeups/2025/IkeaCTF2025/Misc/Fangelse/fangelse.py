flagbuf = open("flag.txt", "r").read()

while True:
    try:
        print(f"Side-channel: {len(flagbuf) ^ 0x1337}")
    # Just in case..
    except Exception as e:
        # print(f"Error: {e}") # don't want to leak anything
        exit(1337)
    code = input("Code: ")
    if len(code) > 5:
        print("nah")
        continue
    exec(code)