import chess, chess.pgn

class cipherBoard:
    # First value of each column is the bottom,think that white is on bottom
    # (In other words you are on the white side)
    board = {
        "a":[],
        "b":[],
        "c":[],
        "d":[],
        "e":[],
        "f":[],
        "g":[],
        "h":[],
    }

    columns = "abcdefgh"
    
    def populate_board(self, text:str): 
        str_position = 0
        for i in range(8):
            for j in self.columns:
                # If there is still message to add
                if str_position < len(text):
                    # Load backwards to make it map like we or white side
                    self.board[j].insert(0, text[str_position])
                    str_position += 1
                else:
                    self.board[j].insert(0, " ")
            
    def print_board(self): 
        for x in reversed(range(8)):
            row = []
            for j in self.columns:
                row.append(self.board[j][x])
            print(row)
        print("\n\n")

    def print_text(self):
        string = ""
        for x in reversed(range(8)):
            for j in self.columns:
                string += self.board[j][x]
        print(string)

    # f is from, t is to. So swap the board values of the two positions
    def swap_move(self, f:str, t:str):
        f_alpha = f[0]
        f_num = int(f[1])
        t_alpha = t[0]
        t_num = int(t[1])
        f = self.board[f_alpha][f_num-1]
        to = self.board[t_alpha][t_num-1]
        self.board[f_alpha][f_num-1] = to
        self.board[t_alpha][t_num-1] = f

    def encrypt(self, moves:list):
        for x in moves:
            f = x[0:2]
            t = x[2:]
            self.swap_move(f, t)

    def decrypt(self, moves:list):
        self.encrypt(reversed(moves))

board = chess.Board()
moves = [] 
pgn = open("2025-05-09_Alice_vs_Bob.pgn")
game = chess.pgn.read_game(pgn)

for number, move in enumerate(game.mainline_moves()): 
    chess_move = board.push(move)
    moves.append(str(move))

cipherB = cipherBoard()

file = open("../message.txt", 'r')
text = file.read()
cipherB.populate_board(text)

cipherB.print_board()

cipherB.decrypt(moves)
cipherB.print_board()

cipherB.print_text()
