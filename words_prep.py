import random

## Open the file with read only permit
f = open('/usr/share/dict/american-english','r')
fw = open('dict-new.txt','w')
## Read the first line 
lines = f.readlines()

## If the file is not empty keep reading line one at a time
## till the file is empty
Nums = 99154
word_list = []
i = 0
while i<1000:
    ln = random.randint(1,99154)
    word = lines[ln].split('\'')[0]
    word = word.split('\n')[0]
    if (word not in word_list) and (len(word) > 5) and (len(word) <= 8): 
        fw.write(word+'\n')
        word_list.append(word)
        i += 1
#print(len(word_list), word_list)
fw.close()
f.close()
