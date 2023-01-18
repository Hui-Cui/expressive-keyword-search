'''
Hui Cui et al., Expressive Keyword Search based on KP-ABE
 
| From: "Expressive Keyword Search".
| Published in: 2015
| Available from: 
| Notes: 
| Security Assumption: 
|
| type:           ciphertext-policy attribute-based encryption (public key)
| setting:        Pairing

:Authors:    Z. Wan, wanzhiguo@gmail.com 
:Date:            04/12/2015
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
#from charm.toolbox.secretutil import SecretUtil
from secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
####Added by Z. Wan
import copy
#from charm.toolbox.policytree import PolicyParser
from policytree import PolicyParser

# type annotations
pk_t = { 'g':G1, 'u':G1, 'h':G1, 'w':G1, 'g_hat':G2, 'g1':G2, 'g2':G2, 'g3':G2, 'g4':G2, 'e_gg_alpha':GT }
mk_t = {'alpha':ZR, 'd1':ZR, 'd2':ZR, 'd3':ZR, 'd4':ZR}
serverkey_t = { 'pk_s':G2, 'sk_s':ZR }
trap_t = { 'T':G2, 'T1':G1, 'T2':G2, 'T3':G1, 'T4':G1, 'T5':G1, 'T6':G1, 'policy':str} #, 'attributes':str }
ct_t = { 'C':GT, 'D':G2, 'D_i':G1, 'E1':G2, 'E2':G2, 'F1':G2, 'F2':G2, 'kws':str}

debug = True
class KPabe_search(ABEnc):
    """
    >>> from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
    >>> group = PairingGroup('SS512')
    >>> cpabe = CPabe_BSW07(group)
    >>> msg = group.random(GT)
    >>> attributes = ['ONE', 'TWO', 'THREE']
    >>> access_policy = '((four or three) and (three or one))'
    >>> (master_public_key, master_key) = cpabe.setup()
    >>> secret_key = cpabe.keygen(master_public_key, master_key, attributes)
    >>> cipher_text = cpabe.encrypt(master_public_key, msg, access_policy)
    >>> decrypted_msg = cpabe.decrypt(master_public_key, secret_key, cipher_text)
    >>> msg == decrypted_msg
    True
    """ 
         
    def __init__(self, groupObj):
        ABEnc.__init__(self)
        global util, group
        util = SecretUtil(groupObj, verbose=False)
        group = groupObj

    @Output(pk_t, mk_t)    
    def setup(self):
        g, g_hat = group.random(G1), group.random(G2)
        u, h, w = group.random(G1), group.random(G1), group.random(G1) 
        alpha, d1, d2, d3, d4 = group.random(ZR), group.random(ZR), group.random(ZR), group.random(ZR), group.random(ZR)  # size of ZR?
  
        ## initialize pre-processing for generators
        g.initPP(); g_hat.initPP()        

        g1 = g_hat ** d1
        g2 = g_hat ** d2
        g3 = g_hat ** d3
        g4 = g_hat ** d4

        e_gg_alpha = pair(g, g_hat ** alpha)
        
        pk = { 'g':g, 'u':u, 'h':h, 'w':w, 'g_hat':g_hat, 'g1':g1, 'g2':g2, 'g3':g3, 'g4':g4, 'e_gg_alpha':e_gg_alpha }
        mk = {'alpha':alpha, 'd1':d1, 'd2':d2, 'd3':d3, 'd4':d4 }
        return (pk, mk)

    @Input(pk_t)
    @Output(serverkey_t)
    def skeygen(self, pk):
        gamma = group.random(ZR)
        pk_s = pk['g_hat'] ** gamma
        sk_s = gamma
        return { 'pk_s':pk_s, 'sk_s':sk_s }        
    
    @Input(mk_t, pk_t, serverkey_t, str)
    @Output(trap_t)
    def trapdoor(self, mk, pk, serverkey, policy_str): 
        print("Debug: policy--->")
        policy = util.createPolicy(policy_str)
        print("Debug: policy--->")
        print("Debug: policy--->", policy_str, policy)

        # making a stripped policy tree, removing keyword values
        policy_stripped = copy.deepcopy(policy)    # util.strip_policy(policy_str)
        parser = PolicyParser()
        parser.policy_strip(policy_stripped)

        if debug: print("\nPolicy:",policy, "\nPolicy without values:",policy_stripped)
        
        a_list = util.getAttributeList(policy)
        #s = group.random(ZR)
        shares = util.calculateSharesDict(mk['alpha'], policy)      
        if debug: print("\nLSSS shares: ",shares)
        #print("printing a_list: ",a_list)

        r = group.random(ZR)
        T = pk['g_hat'] ** r
        T1, T2, T3, T4, T5, T6 = {}, {}, {}, {}, {}, {}
        for i in shares.keys():
            j = util.strip_index(i)   # Remove the index of repeated attribute
            k = j.split(':')[0]
            t1, t2 = group.random(ZR), group.random(ZR)
            T1[k] = pk['g'] ** shares[i]*pk['w']**(mk['d1']*mk['d2']*t1+mk['d3']*mk['d4']*t2)
            T2[k] = serverkey['pk_s']**r*pk['g_hat']**(mk['d1']*mk['d2']*t1+mk['d3']*mk['d4']*t2) 
            #print("in trapdoor2", j, group.hash(j, ZR)) 
            T3[k] = ((pk['u']**(group.hash(j, ZR))*pk['h'])**t1)**(-mk['d2'])
            T4[k] = ((pk['u']**(group.hash(j, ZR))*pk['h'])**t1)**(-mk['d1'])
            T5[k] = ((pk['u']**(group.hash(j, ZR))*pk['h'])**t2)**(-mk['d4'])
            T6[k] = ((pk['u']**(group.hash(j, ZR))*pk['h'])**t2)**(-mk['d3'])
        return { 'T':T, 'T1':T1, 'T2':T2, 'T3':T3, 'T4':T4, 'T5':T5, 'T6':T6, 
            'policy':str(policy_stripped) } #, 'attributes':a_list }   # Don't need the attribute list... } 
    
    @Input(pk_t, list)
    @Output(ct_t)
    def encrypt(self, pk, W):
        mu = group.random() 
        C = pk['e_gg_alpha']**mu
        D = pk['g_hat']**mu
        D_i, E1, E2, F1, F2 = {}, {}, {}, {}, {}
        for i in W:
            z = group.random()      # default: ZR
            s1, s2 = group.random(ZR), group.random(ZR)
            j = i.split(':')[0]                        # Note the difference between i and j. i is the attr used to encrypt, while j is a label.
            D_i[j] = pk['w']**(-mu)*(pk['u']**group.hash(i,ZR)*pk['h'])**z
            E1[j] = pk['g1']**(z-s1)
            E2[j] = pk['g2']**(s1)
            F1[j] = pk['g3']**(z-s2)
            F2[j] = pk['g4']**(s2)

        keywords_stripped = util.keywords_strip(W)
        return { 'C':C, 'D':D, 'D_i':D_i, 'E1':E1, 'E2':E2, 'F1':F1, 'F2':F2, 'kws':str(keywords_stripped) }
    
    @Input(pk_t, trap_t, ct_t, serverkey_t)
    #@Output(ZR)
    def test(self, pk, trap, ct, serverkey):
        if debug: print("\nTrapdoor's policy: ", trap['policy'])
        policy = util.createPolicy(trap['policy'])
        if debug: print("\nCiphertext keywords: ", ct['kws'])
        # with the last parameter as 1, it will return all possible lists of keywords. Z. Wan
        pruned_list = util.prune(policy, ct['kws'], 1)        
        if debug: print("\nKeywords selected to satisfy the policy: ",pruned_list)
        if pruned_list == False:
            return [0,0,0]
        z = util.getCoefficients(policy)
        #print("\nCoefficients for Test: ",z)
        rslt = 0
        num_keywords = 0
        num_tests = 0
        for attr_list in pruned_list:
            if debug: print("\nKeywords for testing:", attr_list)
            A = 1 
            for i in attr_list:
                j = i.getAttributeAndIndex(); k = i.getAttribute()     # No need AndIndex. Z. Wan
    
                #print("\nKeyword to be processed:", j)
                
                B = ( pair(trap['T1'][k], ct['D']) * pair(ct['D_i'][k], trap['T2'][k]/trap['T']**serverkey['sk_s']) * 
                       pair(trap['T3'][k], ct['E1'][k]) * pair(trap['T4'][k], ct['E2'][k]) * 
                       pair(trap['T5'][k], ct['F1'][k]) * pair(trap['T6'][k], ct['F2'][k]) ) ** z[j]
                A *= B
            #print("\nTest computation (e(g,g)^alpha*mu):", A)
            #print("\nCiphertext data (e(g,g)^alpha*mu):", ct['C'])
            num_tests += 1
            num_keywords += len(attr_list)
            if ( A == ct['C'] ):
                #print("\nSearch trial succeeds!")
                print("Success:",len(attr_list))
                rslt = 1
                break
            else:
                #print("\nSearch trail failed!")
                print("Failure:", len(attr_list))
                rslt = 99

        return [num_tests, num_keywords, rslt]


def main():   
    ####################################################
    # Test1 for the keyword search scheme. Z. Wan
    groupObj = PairingGroup('SS512')

    abe_search = KPabe_search(groupObj)
    attrs = ['Illness:Diabetes', 'Sex:Male', 'Weight:100', 'Age:50']
    attrs_upper = []
    for i in attrs:
        attrs_upper.append(i.upper())
    access_policy = '((Weight:100 or Sex:Female) and (Illness:Diabetes or Age:40))'
    if debug:
        print("Attributes =>", attrs); print("Policy =>", access_policy)

    (pk, mk) = abe_search.setup()

    serverkey = abe_search.skeygen(pk)

    trap = abe_search.trapdoor(mk, pk, serverkey, access_policy)
    if debug: print("\ntrapdoor =>", trap)

    ct = abe_search.encrypt(pk, attrs_upper)
    if debug: print("\nciphertext =>", ct)

    rslt = abe_search.test(pk, trap, ct, serverkey)

    print("result => ", rslt)
    #######################################################
   
    # Test2 for the group and its hash

    #groupObj = PairingGroup('MNT224')
    #val = groupObj.hash("aaaa:bbbb", ZR)
    #print(val)

if __name__ == "__main__":
    debug = True
    main()
  
