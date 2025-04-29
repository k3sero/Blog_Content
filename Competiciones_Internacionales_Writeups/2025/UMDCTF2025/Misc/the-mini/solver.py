import puz

p = puz.read('the_mini.puz')

for i in range(1000000):
    if p.unlock_solution(i):
        print(i)
        print(p.solution)