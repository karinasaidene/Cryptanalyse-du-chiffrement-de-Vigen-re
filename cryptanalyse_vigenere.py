# Sorbonne Université 3I024 2021-2022
# TME 2 : Cryptanalyse du chiffre de Vigenere
#
# Etudiant.e 1 : TAFOUGHALT 21200397
# Etudiant.e 2 : SAIDENE 21209708

import sys, getopt, string, math

# Alphabet français
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

#Question 1 :
# Fréquence moyenne des lettres en français
freq_FR = [0.09213414037491088, 0.010354463742221126, 0.030178915678726964, 0.03753683726285317, 0.17174710607479665, 0.010939030914707838, 0.01061497737343803, 0.010717912027723734, 0.07507240372750529, 0.003832727374391129, 6.989390105819367e-05, 0.061368115927295096, 0.026498684088462805, 0.07030818127173859, 0.049140495636714375, 0.023697844853330825, 0.010160031617459242, 0.06609294363882899, 0.07816806814528274, 0.07374314880919855, 0.06356151362232132, 0.01645048271269667, 1.14371838095226e-05, 0.004071637436190045, 0.0023001447439151006, 0.0012263202640210343]

################   Réponses_aux_questions   ################

#   CryptAnalyse V1 :
#       18 textes correctement cryptanalysés.
#       Ce résultat est dû aux différentes hypothèses qu'on avait fait, par exemple la lettre 
#       qui apparaît le plus est toujours E ce qui n'est pas toujours le cas pour de petits textes.
#       En effet, les colonnes des petits textes sont petites et ne fournissent pas assez d'indices sur les décalages.
#
#   CryptAnalyse V2 :
#       43 textes correctement cryptanalysés.
#       Dans cette version aussi c'est toujours la taille petite des textes qui cause probléme
#       En effet le calcul de l'ICM sur des petits textes ne donne pas assez d'information
#
#   CrypAnalayse V3 :
#       84 textes correctement cryptanalysés.
#       Cette version est la meilleure parmi les 3
#       et les textes qui echouent sont aussi les textes courts

# Cette fonction retourne la fréquence de toutes les lettres de l'alphabet de la langue française
def frequence(nomF):
    """
    @param nomF : nom d'un fichier nettoye
    """
    freq_FR = [0.0] * 26
    f = open(nomF , "r")
    text = f.read()
    length = len(text)
    if length != 0 : 
        for i in range(len(alphabet)):
            freq_FR[i] = text.count(alphabet[i])
    return freq_FR
    
freq_FR =  frequence("germinal_nettoye")   

#Question 2 :
# Chiffrement César
def chiffre_cesar(txt, key):
    """
    @param key : cle du chifrement 
    @param txt : le texte à chiffrer (il doit etre en majuscule)
    @return result : le résultat du chiffrement
    """
    result = ""
    for c in txt:
        new_c = (ord(c)%ord('A') + key )%26 + ord('A')
        result += chr(new_c)
    return result


# Déchiffrement César
def dechiffre_cesar(txt, key):
    """
    @param key : cle du déchifrement 
    @param txt : le texte à déchiffrer (il doit etre en majuscule)
    @return result : le résultat du déchiffrement
    """
    result = ""
    for c in txt:
        new_c = (ord(c)%ord('A') - key )%26 + ord('A')
        result += chr(new_c)
    return result

#Question 3 :    
# Chiffrement Vigenere
def chiffre_vigenere(txt, key):
    """
    @param key : cle du chifrement 
    @param txt : le texte à chiffrer (il doit etre en majuscule)
    @return result : le résultat du chiffrement
    """
    result = ""
    length_key = len(key)
    cpt = 0
    for c in txt :
        result += chiffre_cesar(c , key[cpt])
        cpt = (cpt + 1) % length_key
    return result

# Déchiffrement Vigenere
def dechiffre_vigenere(txt, key):
    """
    @param key : cle du déchifrement 
    @param txt : le texte à déchiffrer (il doit etre en majuscule)
    @return result : le résultat du déchiffrement
    """
    result = ""
    length_key = len(key)
    cpt = 0
    for c in txt :
        #k = ord(key[cpt]) % ord('A')
        result += dechiffre_cesar(c , key[cpt])
        cpt = (cpt + 1) % length_key
    return result


# Analyse de fréquences
def freq(txt):
    """
    @param txt: texte dans lequel on calcule l'occurence de chaque lettre de l'alphabet
    @return hist : c'est la tableau d'occurence de chaque lettre de l'alphabet apparut dans le texte 
    """
    hist=[0.0]*len(alphabet)
    if len(txt) != 0 : 
        for i in range(len(alphabet)):
            hist[i] = txt.count(alphabet[i])
    return hist

# Renvoie l'indice dans l'alphabet
# de la lettre la plus fréquente d'un texte
def lettre_freq_max(txt):
    """
    @param txt : le texte dont lequel on cherche l'indice de la lettre ayant la frequence maximale 
    @return : l'indice de la lettre ayant la frequence maximale 
    """
    occ=freq(txt)
    return occ.index(max(occ))

# indice de coïncidence
def indice_coincidence(hist):
    """
    @param hist : tableau qui correspond aux occurences des lettres d'un texte
    @return ic : indice de coincidence
    """
    ic = 0
    n = sum(hist)
    for i in range(len(alphabet)) :
        ic += ((hist[i]*(hist[i]-1))/(n * (n-1)))
    return ic

# Recherche la longueur de la clé
def longueur_clef(cipher):
    """
    @param cipher : le texte chiffré dans lequel on detcte la longueur de la clé
    @return : la longueur de la clés
    
    """
    for k in range(2,21):
        IC_moyen = 0
        m_bloc = [[] for i in range(k)]
        for i in range(k):
            m_bloc[i]= [cipher[j] for j in range(i, len(cipher), k )]
            IC_moyen += indice_coincidence (freq(''.join(m_bloc[i])))
        IC_moyen /= k
        if IC_moyen >0.06  : 
            return k
    return k
    
# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en utilisant la lettre la plus fréquente
# de chaque colonne
def clef_par_decalages(cipher, key_length):
    """
    @param cipher : le texte chiffré 
    @param key_length :  la longueur de la clé avec laquelle le texte a ètait chiffré 
    @return decalages: la clé sous forme de tableau de décalages
    """
    decalages=[0]*key_length
    m_bloc = [[] for i in range(key_length)]
    for i in range(key_length):
        m_bloc[i]= [cipher[j] for j in range(i, len(cipher), key_length )]
        l_max = lettre_freq_max(''.join(m_bloc[i]))
        decalages[i] = (l_max - freq_FR.index(max(freq_FR) ))% 26
    return decalages

# Cryptanalyse V1 avec décalages par frequence max
def cryptanalyse_v1(cipher):
    """
    @param cipher : le texte chiffré 
    @return : le texte cryptanalysé
    """
    key = clef_par_decalages(cipher, longueur_clef(cipher))

    return dechiffre_vigenere(cipher , key) 

################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V2.

# Indice de coincidence mutuelle avec décalage
def indice_coincidence_mutuelle(h1,h2,d):
    """
    @Param h1 : tableau de frequence du texte 1
    @Param h2 : tableau de frequence du texte 2 à decaler
    @Param d : l'indice de decalage
    @Return : indice de coicidence mutuelle des deux texte1 et texte2 decalé avec d positions
    """
    h2_dec = [0] * len(h2)
    for i in range(len(h2)) :
        h2_dec[(i-d)%26] = h2[i]
    IC_mutuelle = 0
    n1 = 0
    n2 = 0
    n1 = sum([h1[i] for i in range (len(h1))])
    n2 = sum([h2_dec[i] for i in range (len(h2_dec))])
    for j in range(26) : 
        IC_mutuelle += ( h1[j]* h2_dec[j] ) 
    
    IC_mutuelle /= n1 * n2
    return IC_mutuelle
    
    

# Renvoie le tableau des décalages probables étant
# donné la longueur de la clé
# en comparant l'indice de décalage mutuel par rapport
# à la première colonne
def tableau_decalages_ICM(cipher, key_length):
    """
    @Param cypher : le text chiffré avec vigénére
    @Param key_length : la taille de la clé avec laquelle le texte a était chiffré
    @Return decalages : le tableau de déclage qui corespond au décalage de chaque colonne par rapport à la premiére colonne
    """
    decalages=[0]*key_length
    m_bloc = [[] for i in range(key_length)]
    for i in range(key_length):
        m_bloc[i]= [cipher[j] for j in range(i, len(cipher), key_length )]
    t1 = freq(''.join(m_bloc[0]))
    for i in range(1 , len(m_bloc)):
        ICMs = [0]*26
        for d in range (26) : 
            t2 = freq(''.join(m_bloc[i]))
            ICMs[d] = indice_coincidence_mutuelle(t1,t2,d)
        decalages[i] = ICMs.index(max(ICMs))
    return decalages

# Cryptanalyse V2 avec décalages par ICM
def cryptanalyse_v2(cipher):
    """
    @param cipher : le texte chiffré 
    @return : le texte cryptanalysé

    """
    #on récupére la taille de la clé
    key_length = longueur_clef(cipher)
    #on Récupére le décalage de chaque collonne par rapport à la premiére colonne
    key_decalage = tableau_decalages_ICM(cipher, key_length)
    #on déchiffre avec vigenere pour alligné tous les blocs au mm niveau
    text = dechiffre_vigenere(cipher, key_decalage)
    #on déchiffre avec cesar
    freq_max = lettre_freq_max(text)
    return dechiffre_cesar(text , (freq_max - freq_FR.index(max(freq_FR)) % 26))


################################################################


### Les fonctions suivantes sont utiles uniquement
### pour la cryptanalyse V3.

# Prend deux listes de même taille et
# calcule la correlation lineaire de Pearson
def correlation(L1,L2):
    """
    @param L1, L2 : deux listes de même taille
    @return : La valeur de la corrélation entre L1 et L2
    """
    diviseur_X = 0
    diviseur_Y = 0
    dividende = 0
    L1_mean = 0
    L2_mean = 0
    for x, y in zip(L1, L2) :
        L1_mean += x
        L2_mean += y
    L1_mean = L1_mean / len(L1)
    L2_mean = L2_mean / len(L2)
    for x, y in zip(L1, L2) :
        X = (x-L1_mean)
        Y = (y-L2_mean)
        dividende += X*Y
        diviseur_X += X*X
        diviseur_Y += Y*Y
    diviseur_X = math.sqrt(diviseur_X)
    diviseur_Y = math.sqrt(diviseur_Y)
    return round(dividende / (diviseur_X * diviseur_Y),4)

# Renvoie la meilleur clé possible par correlation
# étant donné une longueur de clé fixée
def clef_correlations(cipher, key_length):
    """
    @param cipher : texte chiffré
    @param key_length : la taille de la clé avec la quelle le texte cipher est chiffré
    @return : la moyenne sur les colonnes des corrélations maximales obtenues, et un tableau contenant pour chaque colonne le décalage qui maximise la corrélation.
    """
    freq_FR =  frequence("germinal_nettoye")  

    key=[0]*key_length
    score = 0.0

    m_bloc = [[] for i in range(key_length)]
    for i in range(key_length):
        m_bloc[i]= [cipher[j] for j in range(i, len(cipher), key_length )]
    
    for i in range(0 , key_length):
        correlations = [0]*26
        for d in range (26) :
            h2 = freq(''.join(m_bloc[i]))
            h2_dec = [0] * len(h2)
            for j in range(len(h2)) :
                h2_dec[(j-d)%26] = h2[j]
            correlations[d] = correlation(freq_FR,h2_dec)
        max_corr = max(correlations)
        key[i] = correlations.index(max_corr)
        score +=  max_corr
    
    return (score/key_length, key)

# Cryptanalyse V3 avec correlations
def cryptanalyse_v3(cipher):
    """
    param cipher : le texte chiffré 
    @return : le texte cryptanalysé
    """
    score_max = 0
    key_max = []
    for i in range (2, 21) :
        score , key = clef_correlations(cipher, i)
        if score > score_max : 
            key_max = key
            score_max = score
    return dechiffre_vigenere(cipher,key_max)



################################################################
# NE PAS MODIFIER LES FONCTIONS SUIVANTES
# ELLES SONT UTILES POUR LES TEST D'EVALUATION
################################################################


# Lit un fichier et renvoie la chaine de caracteres
def read(fichier):
    f=open(fichier,"r")
    txt=(f.readlines())[0].rstrip('\n')
    f.close()
    return txt

# Execute la fonction cryptanalyse_vN où N est la version
def cryptanalyse(fichier, version):
    cipher = read(fichier)
    if version == 1:
        return cryptanalyse_v1(cipher)
    elif version == 2:
        return cryptanalyse_v2(cipher)
    elif version == 3:
        return cryptanalyse_v3(cipher)

def usage():
    print ("Usage: python3 cryptanalyse_vigenere.py -v <1,2,3> -f <FichierACryptanalyser>", file=sys.stderr)
    sys.exit(1)

def main(argv):
    size = -1
    version = 0
    fichier = ''
    try:
        opts, args = getopt.getopt(argv,"hv:f:")
    except getopt.GetoptError:
        usage()
    for opt, arg in opts:
        if opt == '-h':
            usage()
        elif opt in ("-v"):
            version = int(arg)
        elif opt in ("-f"):
            fichier = arg
    if fichier=='':
        usage()
    if not(version==1 or version==2 or version==3):
        usage()

    print("Cryptanalyse version "+str(version)+" du fichier "+fichier+" :")
    print(cryptanalyse(fichier, version))
    
if __name__ == "__main__":
   main(sys.argv[1:])
