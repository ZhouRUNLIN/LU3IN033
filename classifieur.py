import os
from analyse import *

path = "trame"
files= os.listdir(path) 
destinationListe = []              #Le classificateur va classer en fonction de l'adresse cible.
    
for file in files:                 #parcours répertoire
    if not os.path.isdir(file):    #Déterminez s'il s'agit d'un dossier, ouvrez-le uniquement s'il ne l'est pas.
        f = open(path+"/"+file) 
        iter_f = iter(f)           #la création d'itération
        str=""                     #stocker la contenue dans le ficher
        for line in iter_f:
            str+=line
        dic=decode_no_CRC(str)
        if dic['Type']=='IP' and dic['IP protocol']=='TCP' and (dic['IP Destination address'] == '192.168.1.45' or dic['IP Source address'] == '192.168.1.45'):
            if dic['IP Destination address'] != '192.168.1.45' and dic['IP Destination address'] not in destinationListe:  
                destinationListe.append(dic['IP Destination address'])
            if dic['IP Source address'] != '192.168.1.45' and dic['IP Source address'] not in destinationListe:
                destinationListe.append(dic['IP Source address'])
        else:
            os.remove(path+"/"+file)

print(set(destinationListe))

path = "trame"
files= os.listdir(path) 
dicVide={}
for i in range(len(destinationListe)):
    listeFile=[]
    for file in files:                 
        if not os.path.isdir(file):    
            f = open(path+"/"+file) 
            iter_f = iter(f)          
            str=""                     
            for line in iter_f:
                str+=line
            dic=decode_no_CRC(str)
            if dic['IP Destination address']==destinationListe[i] or dic['IP Source address']==destinationListe[i]:
                listeFile.append(path+"/"+file)
    dicVide[destinationListe[i]]=listeFile

print(len(dicVide[destinationListe[0]]))
print(len(dicVide[destinationListe[1]]))
print(len(dicVide[destinationListe[2]]))
