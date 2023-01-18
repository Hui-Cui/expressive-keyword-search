'''
Experiments for Expressive Keyword Search 

:Authors:    Z. Wan, wanzhiguo@gmail.com
:Date:            06/12/2015
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT#,pair
#from charm.schemes.abenc.abe_search import KPabe_search
from abe_search import KPabe_search
from charm.core.engine.util import objectToBytes,bytesToObject
import random


debug = False

def wordList_prep(num_words):
    ## Open the file with read only permit
    f = open('./dict-new.txt','r')
    lines = f.readlines()
    
    word_list = []
    #random.seed(1207)
    i = 0
    indices = random.sample(range(1, 1000), num_words)
    for i in indices:
        word = lines[i]
        word = word.split('\n')[0]
        word_list.append(word.upper())
    f.close()
    return word_list

def policy_from_keywords(keywords_list): #, num_policy):
    #if len(keywords_list) != 2** exponent: return
    length = len(keywords_list)
    if length == 1: return keywords_list[0]
    leftstr = policy_from_keywords(keywords_list[:length-int(length/2)])
    rightstr = policy_from_keywords(keywords_list[length-int(length/2):])
    rnd = random.randint(1,2)
    if rnd == 1: return '(' + leftstr + " AND " + rightstr + ')'
    if rnd == 2: return '(' + leftstr + " OR " + rightstr + ')'

def keywords_prep(names_list, num_keywords, num_values):
    # Construct keyword names and values. names are from english words, while values from 1 to 10
    # keyword name: non-repeated, 4-8 symbols, without "'s"
    #random.seed(1206)
    names = []
    num_total = len(names_list)
    print("total:", num_total, num_keywords)
    indices = random.sample(range(1, num_total), num_keywords)
    for i in indices:
        names.append(names_list[i])
    i = 0
    keywords = []
    while i< num_keywords:
        value = random.randint(1, num_values)
        kw = names[i] + ':' + str(value)
        keywords.append(kw)
        i += 1
    #print("Keywords => ", keywords)
    return  keywords 

def policy_construct(names_list, num_policy, num_values):
    # Construct policy
    # exp = 3
    #num_policy = 6     # [2,4,8,16,32,64,128],  it should be always smaller than the size of word_list
    names_in_policy = []
    num_total = len(names_list)
    print("num_total:", num_total, num_policy)
    indices = random.sample(range(1, num_total), num_policy)
    # print(indices)
    for i in indices:
        names_in_policy.append(names_list[i])
    # print(names_in_policy, "length:", len(names_in_policy))
    i = 0
    keywords_in_policy = []
    while i< num_policy:
        value = random.randint(1, num_values)
        kw = names_in_policy[i] + ':' + str(value)
        keywords_in_policy.append(kw)
        i += 1

    policy_str = policy_from_keywords(keywords_in_policy)# , num_policy)

    return policy_str

def run_test(num_total, num_keywords, num_values, num_in_policy, num_ciphertext, num_policy_str):
    #random.seed(1208)
    groupObj = PairingGroup('MNT224')

    abe_search = KPabe_search(groupObj)

    (pk, mk) = abe_search.setup()
    
    serverkey = abe_search.skeygen(pk)

    # Construct policy
    names_list = wordList_prep(num_total)       # construct the keyword name list, without keyword values
    # print(policy_str)

    i, j = 0, 0
    trap, policy_str, ct, rslt = [], [], [], []
    rslt_trap, rslt_encrypt = [], []
    while i < num_policy_str:
        policy_str.append(policy_construct(names_list, num_in_policy, num_values))
        assert groupObj.InitBenchmark(), "failed to initialize benchmark"
        groupObj.StartBenchmark(["RealTime", "Exp", "Pair", "Granular"])

        trap.append(abe_search.trapdoor(mk, pk, serverkey, policy_str[i]))
        #print("trapdoor =>", trap)
        groupObj.EndBenchmark()
        # obtain results
        msmtDict = groupObj.GetGeneralBenchmarks()
        granDict = groupObj.GetGranularBenchmarks()
        print("<=== General Benchmarks ===>")
        print("Results  := ", msmtDict)
        print("<=== Granular Benchmarks ===>")
        #print("ZR mul   := ", granDict["Mul"][ZR], "ZR exp   := ", granDict["Exp"][ZR])
        print("G1 exp   := ", granDict["Exp"][G1])
        print("G2 exp   := ", granDict["Exp"][G2])
        print("GT exp   := ", granDict["Exp"][GT])

        temp = []
        temp.append(granDict["Exp"][G1])
        temp.append(granDict["Exp"][G2])
        temp.append(granDict["Exp"][GT])
        temp.append(msmtDict["Exp"])
        temp.append(msmtDict["Pair"])
        temp.append(msmtDict["RealTime"])
        rslt_trap.append(temp)

        i += 1

    while j < num_ciphertext:
        keywords = keywords_prep(names_list, num_keywords, num_values)

        assert groupObj.InitBenchmark(), "failed to initialize benchmark"
        groupObj.StartBenchmark(["RealTime", "Exp", "Pair", "Granular"])

        ct.append(abe_search.encrypt(pk, keywords))
        #print("ciphertext =>", ct)
        #ct_ser = objectToBytes(ct, groupObj)
        #print(ct_ser)
        #ct_recover = bytesToObject(ct_ser, groupObj)
        #print(ct_recover)
        #print("----------------------")
        #print(ct)
        
        groupObj.EndBenchmark()
        # obtain results
        msmtDict = groupObj.GetGeneralBenchmarks()
        granDict = groupObj.GetGranularBenchmarks()
        print("<=== General Benchmarks ===>", msmtDict)
        print("<=== Granular Benchmarks ===>", granDict)
        print("G1 exp   := ", granDict["Exp"][G1])
        print("G2 exp   := ", granDict["Exp"][G2])
        print("GT exp   := ", granDict["Exp"][GT])
        temp = []
        temp.append(granDict["Exp"][G1])
        temp.append(granDict["Exp"][G2])
        temp.append(granDict["Exp"][GT])
        temp.append(msmtDict["Exp"])
        temp.append(msmtDict["Pair"])
        temp.append(msmtDict["RealTime"])
        rslt_encrypt.append(temp)
        j += 1
    
    i, j  = 0, 0
    #tt = 0
    while i < num_policy_str:
        j = 0
        while j < num_ciphertext:
        
            assert groupObj.InitBenchmark(), "failed to initialize benchmark"
            groupObj.StartBenchmark(["RealTime", "Exp", "Pair", "Granular"])

            temp = abe_search.test(pk, trap[i], ct[j], serverkey)

            groupObj.EndBenchmark()
            print(temp)
            if temp[2] != 0:
            # obtain results
                msmtDict = groupObj.GetGeneralBenchmarks()
                granDict = groupObj.GetGranularBenchmarks()
                print("<=== General Benchmarks ===>")
                print("Results  := ", msmtDict)
                print("<=== Granular Benchmarks ===>", granDict) #, rslt[i][j][0], rslt[i][j][1])
                print("G1 exp   := ", granDict["Exp"][G1])
                print("G2 exp   := ", granDict["Exp"][G2])
                print("GT exp   := ", granDict["Exp"][GT])
                temp.append(granDict["Exp"][G1])
                temp.append(granDict["Exp"][G2])
                temp.append(granDict["Exp"][GT])
                temp.append(msmtDict["Exp"])
                temp.append(msmtDict["Pair"])
                temp.append(msmtDict["RealTime"])
                #rslt[i].append(abe_search.test(pk, trap[i], ct[j], serverkey))
                rslt.append(temp)
            #tt+=1
            #print(i,j,tt)

            j += 1
        i = i+1
    return (rslt, rslt_trap, rslt_encrypt)

def main():   
    ## Construct keyword names and values. names are from english words, while values from 1 to 10
    ## keyword name: non-repeated, 4-8 symbols, without "'s"
    # num_total = [2, 4, 8, 12, 16, 20, 28, 36, 48, 60]       # Num of all keywords, from the dictionary
    #num_total = 40       # Num of all keywords, from the dictionary
    #num_keywords = 30    # Num of keywords in the ciphertext
    #num_values = 3       # Num of keyword values for each keyword
    #num_in_policy = 30   # Num of keywords in a policy

    num_total = 500            # Num of all keywords, from the dictionary
    num_keywords = [10, 20, 30, 40, 50]    # Num of keywords in the ciphertext
    num_values = 2       # Num of keyword values for each keyword
    num_in_policy = [2, 4, 6, 8, 10]   # Num of keywords in a policy

    num_ciphertext = 1000
    num_policy_str = 10

    #filename = str("rslt-search-100-100-3")
    f_test = open('./rslt-search-100-100-3-MNT224-test-X','w')
    f_trap = open('./rslt-search-100-100-3-MNT224-trap-X','w')
    f_enc = open('./rslt-search-100-100-3-MNT224-enc-X','w')
    for i in num_keywords:
        for j in num_in_policy:
            (rslt, rslt_trap, rslt_encrypt) = run_test(num_total, i, num_values, j, num_ciphertext, num_policy_str)
            #(rslt, rslt_trap, rslt_encrypt) = run_test(i+2, i, num_values, j, num_ciphertext, num_policy_str)
            for k in rslt: f_test.write(str(i)+","+str(j)+","+",".join([str(int_str) for int_str in k])+"\n")
            for k in rslt_trap: f_trap.write(str(i)+","+str(j)+","+",".join([str(int_str) for int_str in k])+"\n")
            for k in rslt_encrypt: f_enc.write(str(i)+","+str(j)+","+",".join([str(int_str) for int_str in k])+"\n")
            #f.write(str(i) +":"+ str(j)+":"+  str(rslt)+":"+ str(rslt_trap)+":"+  str(rslt_encrypt)+"\n")
    f_test.close()
    f_trap.close()
    f_enc.close()


if __name__ == "__main__":
    debug = True
    main()
   
