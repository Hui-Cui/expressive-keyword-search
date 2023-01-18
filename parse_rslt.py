import sys

a = [10,20,30,40,50]
b = [2,4,6,8,10]

idx = 0
count = [0]*25
sums = [0]*25
for i in open(sys.argv[1]).readlines():
    rslts = i.split(',')
    #print(rslts[0])
    idx = (a.index(int(rslts[0])))*5 + b.index(int(rslts[1]))
    count[idx] += 1
    sums[idx] += float(rslts[10])
i = 0
#print(count)
#print(sums)
aver = [0]*25
while i< 25 and count[i] != 0:
    aver[i] = sums[i]/count[i]
    print(aver[i])
    i += 1
print(aver)
