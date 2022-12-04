import os
from analyse import *

path = "trame"
files= os.listdir(path) 
destinationListe = []              #Le classificateur va classer en fonction de l'adresse cible.


f=open("trame/trame1.txt")
iter_f = iter(f)           #la création d'itération
str=""                     #stocker la contenue dans le ficher
for line in iter_f:
    str+=line
print(decode_no_CRC(str))
    
"""
for file in files:                 #parcours répertoire
    if not os.path.isdir(file):    #Déterminez s'il s'agit d'un dossier, ouvrez-le uniquement s'il ne l'est pas.
        f = open(path+"/"+file) 
        iter_f = iter(f)           #la création d'itération
        str=""                     #stocker la contenue dans le ficher
        for line in iter_f:
            str+=line
        print(decode_no_CRC(str))
        #dic=decode_no_CRC(str)
        #print(dic['Eth Destination address'])     
"""