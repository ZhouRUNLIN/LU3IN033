
#Outils
def h2d_half(s:str):
    """
    len(s)==1
    Calculer la valeur décimale d'un demi-octet
    """
    assert len(s)==1
    return int(s,16)

def h2d_byte(s:str):
    """
    len(s)==2
    Calculer la valeur décimale d'un octet
    """
    assert len(s)==2
    return int(s,16)

def discharge(s:str,n:int):
    """
    décharger n octets.
    return: ([liste des octets],str reste)
    """
    if n==0:
        return ([],s)
    if ' ' not in s:
        assert n==1
        return ([s],"")
    l,sr=discharge(s[3:],n-1)
    return ([s[0:2]]+l,sr)

def merge_dict(a:dict,b:dict):
    a.update(b)
    return a

# Debut
def decode(s:str):
    """
    Décoder la trame, retournant un dictionnaire
    """
    return eth_preamble(s)

def decode_no_CRC(s:str):
    return eth_dest_addr(s)

# ethernet
def eth_preamble(s:str):
    """
    preamble : 8 octets inutiles
    """
    l,sr=discharge(s,8)
    return eth_dest_addr(sr)

def eth_dest_addr(s:str):
    """
    Destination address : 6 octets
    L'adresse physique (MAC) du destinataire de la trame
    """
    l,sr=discharge(s,6)
    addr=""
    for byte in l:
        addr+=byte+":"
    return merge_dict({"Eth Destination address":addr[0:-1]},eth_src_addr(sr))

def eth_src_addr(s:str):
    """
    Source address : 6 octets
    L'adresse physique (MAC) du source de la trame
    """
    l,sr=discharge(s,6)
    addr=""
    for byte in l:
        addr+=byte+":"
    return merge_dict({"Eth Source address":addr[0:-1]},eth_type(sr))

def eth_type(s:str):
    """
    Type : 2 octets
    Protocole de niveau supérieur encapsulé dans le champ Data de la trame.
    """
    l,sr=discharge(s,2)
    type=l[0]+l[1]
    assert type in ["0800","0806"]
    if type=="0800":
        return merge_dict({"Type":"IP"},ip_version_IHL(sr))
    if type=="0806":
        return merge_dict({"Type":"ARP"},arp_hardware(sr))

# ip
def ip_version_IHL(s:str):
    """
    Version : 4 bits
    L'identification de la version courante du protocole
    IHL : 4 bits
    IP Header Length, la longueur de l'en-tête IP exprimée en mots de 32 bits
    !!! Dans le dictionnaire nous le représentons en octets
    """
    l,sr=discharge(s,1)
    version=h2d_half(l[0][0])
    ihl=h2d_half(l[0][1])*4
    return merge_dict({"Version":version,"IHL":ihl},ip_TOS(sr,ihl-1))

def ip_TOS(s:str,IHL:int):
    """
    TOS : 1 octet
    Type of service, le type de service à appliquer au paquet en fonction de certains paramètres comme le délai de transit, la sécurité. Il est peu utilisé et sa valeur est généralement égale à 0.
    """
    l,sr=discharge(s,1)
    tos=l[0]
    return merge_dict({"TOS":tos},ip_totalL(sr,IHL-1))

def ip_totalL(s:str,IHL:int):
    """
    Total length : 2 octets
    La longueur totale du datagramme, exprimée en octets. En pratique, il est rare qu'un datagramme IP fasse plus de 1500 octets
    """
    l,sr=discharge(s,2)
    totalL=h2d_byte(l[0])*256+h2d_byte(l[1])
    return merge_dict({"Total length":totalL},ip_identification(sr,IHL-2,totalL-4))

def ip_identification(s:str,IHL:int,totalL:int):
    """
    Identification : 2 octets
    Sert en cas de fragmentation/réassemblage du datagramme. Ce champ permet alors à l'entité réceptrice de reconnaître les fragments issus d'un même datagramme initial et qui doivent donc faire l'objet d'un réassemblage.
    """
    l,sr=discharge(s,2)
    idf=l[0]+l[1]
    return merge_dict({"Identification":"0x"+idf},ip_flags_fo(sr,IHL-2,totalL-2))

def ip_flags_fo(s:str,IHL:int,totalL:int):
    """
    flags : 3 bits
        bit réservé : mis à 0
        DF (Don't Fragment) : mis à 1 par l'émetteur pour interdire la fragmentation
        MF (More Fragment) : mis à 1 pour signifier que le fragment courant est suivi d'un autre fragment
    fragment offset : 13 bits
    Donner la position relative du fragment dans le datagramme initial, le déplacement étant donné en unités de 64 bits
    """
    l,sr=discharge(s,2)
    num=int(l[0]+l[1],16)
    numBin="{:016b}".format(num)
    assert numBin[0]=='0'
    if numBin[1]=='1':
        f="DF"
    elif numBin[2]=='1':
        f="MF"
    else:
        f="None"
    numBin=numBin[3:]
    fo=int(numBin,2)
    return merge_dict({"flags":f,"Fragment offset":fo},ip_TTL(sr,IHL-2,totalL-2))

def ip_TTL(s:str,IHL:int,totalL:int):
    """
    Identification : 1 octet
    Time To Live, donner une indication de la limite supérieure du temps de vie d'un datagramme
    """
    l,sr=discharge(s,1)
    ttl=h2d_byte(l[0])
    return merge_dict({"TTL":ttl},ip_protocol(sr,IHL-1,totalL-1))

def ip_protocol(s:str,IHL:int,totalL:int):
    """
    Identification : 1 octet
    Le protocole (de niveau supérieur) utilisé pour le champ de données du datagramme.
    """
    l,sr=discharge(s,1)
    protocol=h2d_byte(l[0])
    assert protocol in (1,6,17)
    prot_Name={1:"ICMP",6:"TCP",17:"UDP"}[protocol]
    return merge_dict({"IP protocol":prot_Name},ip_header_checksum(sr,IHL-1,totalL-1,prot_Name))

def ip_header_checksum(s:str,IHL:int,totalL:int,protocol:str):
    """
    Header checksum : 2 octets
    Une zone de contrôle d'erreur portant uniquement sur l'en-tête du datagramme
    """
    l,sr=discharge(s,2)
    cs=l[0]+l[1]
    return merge_dict({"IP Header checksum":"0x"+cs},ip_src_addr(sr,IHL-2,totalL-2,protocol))

def ip_src_addr(s:str,IHL:int,totalL:int,protocol:str):
    """
    Source address : 4 octets
    L’adresse IP de la source du datagramme
    """
    l,sr=discharge(s,4)
    ip=""
    for i in range(4):
        ip+=str(h2d_byte(l[i]))+"."
    ip=ip[0:-1]
    return merge_dict({"IP Source address":ip},ip_dest_addr(sr,IHL-4,totalL-4,protocol))

def ip_dest_addr(s:str,IHL:int,totalL:int,protocol:str):
    """
    Source address : 4 octets
    L’adresse IP de la destination du datagramme
    """
    l,sr=discharge(s,4)
    ip=""
    for i in range(4):
        ip+=str(h2d_byte(l[i]))+"."
    ip=ip[0:-1]
    return {"IP Destination address":ip}

# IP options
def ip_option(s:str,protocol:str,usedLen:int):
    """
    Type : 1 octet
    Length : 1 octet
    Data : Length-2 octets
    """
    l,sr=discharge(s,1)
    if l[0]=="00":
        return ip_option_padding(sr,protocol,usedLen+1)
    oType={1:"NOP",7:"RR",68:"TS",131:"LSR",137:"SSR"}[h2d_byte(l[0])]
    l,sr1=discharge(sr,1)
    oLen=h2d_byte(l[0])
    l,sr2=discharge(sr1,oLen-2)
    oData=""
    for octet in l:
        oData+=octet+" "
    oData=oData[0:-1]
    return merge_dict({"IP Option "+oType:oData},ip_option(sr2,protocol,usedLen+oLen))

def ip_option_padding(s:str,protocol:str,usedLen:int):
    """
    Padding : 0-3 octets
    Permet d'aligner l'en-tête sur 32 bits
    """
    if usedLen%4!=0:
        l,sr=discharge(s,4-usedLen%4)
    if protocol=="ICMP":
        return icmp_start(sr)
    if protocol=="UDP":
        return
    if protocol=="TCP":
        return
    assert False

# ARP
def arp_hardware(s:str):
    """
    Type : 2 octets
    Le type d'interface pour laquelle l'émetteur cherche une réponse
    """
    l,sr=discharge(s,2)
    hw=l[0]+l[1]
    return merge_dict({"Hardware":"0x"+hw},arp_protocol(sr))

def arp_protocol(s:str):
    """
    Type : 2 octets
    Le type d'interface pour laquelle l'émetteur cherche une réponse
    """
    l,sr=discharge(s,2)
    protocol=l[0]+l[1]
    return merge_dict({"Protocol":"0x"+protocol},arp_Hlen(sr))

def arp_Hlen(s:str):
    """
    Type : 1 octet
    La taille de l’adresse physique (Ethernet) en octets
    """
    l,sr=discharge(s,1)
    hlen=h2d_byte(l[0])
    return merge_dict({"Hlen":hlen},arp_Plen(sr))

def arp_Plen(s:str):
    """
    Type : 1 octet
    La taille de l’adresse au niveau protocolaire (IP)
    """
    l,sr=discharge(s,1)
    plen=h2d_byte(l[0])
    return merge_dict({"Plen":plen},arp_operation(sr))

def arp_operation(s:str):
    """
    Type : 2 octets
    Le type d’opération à effectuer par le récepteur
    """
    l,sr=discharge(s,2)
    op=l[0]+l[1]
    return merge_dict({"Operation":"0x"+op},arp_sender_HA(sr))

def arp_sender_HA(s:str):
    """
    Type : 6 octets
    L’adresse physique (Ethernet) de l’émetteur
    """
    l,sr=discharge(s,6)
    addr=""
    for byte in l:
        addr+=byte+":"
    return merge_dict({"Sender HA":addr[0:-1]},arp_sender_IA(sr))

def arp_sender_IA(s:str):
    """
    Type : 4 octets
    L’adresse de niveau protocolaire (IP) demandé de l’émetteur 
    """
    l,sr=discharge(s,4)
    ip=""
    for i in range(4):
        ip+=str(h2d_byte(l[i]))+"."
    ip=ip[0:-1]
    return merge_dict({"Sender IA":ip},arp_target_HA(sr))

def arp_target_HA(s:str):
    """
    Type : 6 octets
    L’adresse physique (Ethernet) du récepteur
    """
    l,sr=discharge(s,6)
    addr=""
    for byte in l:
        addr+=byte+":"
    return merge_dict({"Target HA":addr[0:-1]},arp_target_IA(sr))

def arp_target_IA(s:str):
    """
    Type : 4 octets
    L’adresse de niveau protocolaire (IP) demandé du récepteur 
    """
    l,sr=discharge(s,4)
    ip=""
    for i in range(4):
        ip+=str(h2d_byte(l[i]))+"."
    ip=ip[0:-1]
    return {"Target IA":ip}

#ICMP
def icmp_start(s:str):
    """
    Type : 2 octets
    Est 0x0800 ou 0x0000
    """
    l,sr=discharge(s,2)
    assert l[0] in ["08","00"]
    assert l[1] == "00"
    return icmp_checksum(sr)

def icmp_checksum(s:str):
    """
    Type : 2 octets
    """
    l,sr=discharge(s,2)
    return merge_dict({"ICMP Checksum":"0x"+l[0]+l[1]},icmp_identifier(sr))

def icmp_identifier(s:str):
    """
    Type : 2 octets
    """
    l,sr=discharge(s,2)
    return merge_dict({"ICMP Identifier":"0x"+l[0]+l[1]},icmp_seq(sr))

def icmp_seq(s:str):
    """
    Type : 2 octets
    """
    l,sr=discharge(s,2)
    return merge_dict({"ICMP Sequence number":"0x"+l[0]+l[1]},icmp_opData(sr))

def icmp_opData(s:str):
    """
    Type : 2 octets
    """
    return {"ICMP Optional data":"0x"+s}

