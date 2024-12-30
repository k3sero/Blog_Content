m = 189037830245809490512965016070455766621

def verifyToken(name, mac):
		data = self.name.encode(errors="surrogateescape")
		crc = (1 << 128) - 1
		for b in data:
			crc ^= b
			for _ in range(8):
				crc = (crc >> 1) ^ (m & -(crc & 1))
		return hex(crc ^ ((1 << 128) - 1))[2:] == self.mac



def generateToken(name):
	data = name.encode(errors="surrogateescape")
	crc = (1 << 128) - 1
	for b in data:
		crc ^= b
		for _ in range(8):
			crc = crc & 1 ^ (m & -(crc & 1))
	return hex(crc ^ ((1 << 128) - 1))[2:]

name = str(input("Enter your name: "))
token = generateToken(name)
print(token)