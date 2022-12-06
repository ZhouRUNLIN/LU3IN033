import os
from analyse import *
import linecache


#obtenir l'addresse ip 
def get_line_context(file_path, line_number):
    return linecache.getline(file_path, line_number).strip()

addIP=get_line_context("information.txt", 2)
print("address IP local :" + str(addIP))

def show_highest_protocol(dic):
    bool=1
    for i in ["HTTP Type","HTTP Method","HTTP URL","HTTP Status","HTTP Version","HTTP Message"]:
        if i not in dic.keys():
            bool=0
    if bool==1:
        return "HTTP"
    else:
        bool=1
        for i in ["TCP Source port","TCP Destination port", "TCP Sequence number","TCP Acknowledgement number"]:
            if i not in dic.keys():
                bool=0
        if bool==1:
            return "TCP"
        else:
            return "IP"

path = "trame"
files= os.listdir(path) 
destinationListe = []              #Le classificateur va classer en fonction de l'adresse cible.
for file in files:                 
    if not os.path.isdir(file):
        f=open(path+"/"+file,'rb')
        str=f.read().decode(errors='replace')
        dic=decode_simplified(str)

        bool=1
        for data in ["Type", "IP protocol", "TCP Source port","TCP Destination port", "TCP Sequence number","TCP Acknowledgement number"]:
            if data not in dic.keys():
                bool=0
        
        if bool==1:
            if dic['Type']=='IP' and dic['IP protocol']=='TCP':
                if dic['IP Destination address'] != addIP and dic['IP Destination address'] not in destinationListe:  
                    destinationListe.append(dic['IP Destination address'])
                if dic['IP Source address'] != addIP and dic['IP Source address'] not in destinationListe:
                    destinationListe.append(dic['IP Source address'])
            else:
                os.remove(path+"/"+file)
        else:
            os.remove(path+"/"+file)

print("liste de hôte capturé :")
print(destinationListe)

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
            dic=decode_simplified(str)
            if dic['IP Destination address']==destinationListe[i] or dic['IP Source address']==destinationListe[i]:
                listeFile.append(path+"/"+file)
    dicVide[destinationListe[i]]=listeFile

print("\n")
print("Please select an IP address to view its traffic with this machine")
print("In order to select an IP, please enter on the keyboard the index of the list of ip addresses that appeared before \n(the first element of the list is 0, the second is 1, the n-th is n-1,...)")
a=input("waiting for your choice : ")

listeFile=dicVide[destinationListe[int(a)]]
contenueListe=[]
for i in listeFile:
    line=get_line_context(i, 1)
    line=decode_simplified(line)
    contenueListe.append(line)

#entete
print('IP address'.center(15) + 'port'.center(7) + " ".ljust(20) + " ".rjust(20)+ 'port'.center(7) + 'IP address'.center(15))

for i in range(len(contenueListe)):
    if show_highest_protocol(contenueListe[i])=="HTTP":
        print("HTTP -----")
    if show_highest_protocol(contenueListe[i])=="TCP":
        if contenueListe[i]['IP Destination address']==addIP:
            print(" ".ljust(23), end="")
            print("SN : {:d}   ".format(contenueListe[i]["TCP Sequence number"]), end="")
            print("AN : {:d}   ".format(contenueListe[i]["TCP Acknowledgement number"], end=""))

            print(contenueListe[0]['IP Destination address'].center(15), end='')
            print("{:^7d}".format(contenueListe[0]["TCP Destination port"]), end='')
            print("--------------------", end='')
            print("------------------->", end='')
            print("{:^7d}".format(contenueListe[0]["TCP Source port"]), end='')
            print(contenueListe[0]['IP Source address'].center(15))
        else:
            print(" ".ljust(23), end="")
            print("SN : {:d}   ".format(contenueListe[i]["TCP Sequence number"]), end="")
            print("AN : {:d}   ".format(contenueListe[i]["TCP Acknowledgement number"], end=""))

            print(contenueListe[0]['IP Destination address'].center(15), end='')
            print("{:^7d}".format(contenueListe[0]["TCP Destination port"]), end='')
            print("<-------------------", end='')
            print("--------------------", end='')
            print("{:^7d}".format(contenueListe[0]["TCP Source port"]), end='')
            print(contenueListe[0]['IP Source address'].center(15))
    else:
        print("IP")
