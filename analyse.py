
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

# Debut
def decode(s:str):
    """
    Décoder la trame, retournant un dictionnaire
    """
    return eth_preamble(s)

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
    return {"Destination address":addr[0:-1]}.update(eth_src_addr(sr))

def eth_src_addr(s:str):
    """
    Source address : 6 octets
    L'adresse physique (MAC) du source de la trame
    """
    l,sr=discharge(s,6)
    addr=""
    for byte in l:
        addr+=byte+":"
    return {"Source address":addr[0:-1]}.update(eth_type(sr))

def eth_type(s:str):
    """
    Type : 2 octets
    Protocole de niveau supérieur encapsulé dans le champ Data de la trame.
    """
    l,sr=discharge(s,2)
    type=l[0]+l[1]
    assert type in ["0800","0806"]
    if type=="0800":
        return {"Type":"IP"}.update(ip_version_IHL(sr))
    if type=="0806":
        return {"Type":"ARP"}.update(arp_hardware(sr))

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
    version=h2d_half(l[0])
    ihl=h2d_half(l[1])*4
    return {"Version":version,"IHL":ihl}.update(ip_TOS(sr,ihl-1))

def ip_TOS(s:str,IHL:int):
    """
    TOS : 1 octet
    Type of service, le type de service à appliquer au paquet en fonction de certains paramètres comme le délai de transit, la sécurité. Il est peu utilisé et sa valeur est généralement égale à 0.
    """
    l,sr=discharge(s,1)
    tos=l[0]
    return {"TOS":tos}.update(ip_totalL(sr,IHL-1))

def ip_totalL(s:str,IHL:int):
    """
    Total length : 2 octets
    La longueur totale du datagramme, exprimée en octets. En pratique, il est rare qu'un datagramme IP fasse plus de 1500 octets
    """
    l,sr=discharge(s,1)
    totalL=h2d_byte(l[0])*256+h2d_byte(l[1])
    return {"Total length":totalL}.update(ip_identification(sr,IHL-2,totalL-4))

def ip_identification(s:str,IHL:int,totalL:int):
    """
    Identification : 2 octets
    Sert en cas de fragmentation/réassemblage du datagramme. Ce champ permet alors à l'entité réceptrice de reconnaître les fragments issus d'un même datagramme initial et qui doivent donc faire l'objet d'un réassemblage.
    """
    l,sr=discharge(s,2)
    idf=l[0]+l[1]
    return {"Identification":"0x"+idf}.update(ip_flags_fo(sr,IHL-2,totalL-2))

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
    numBin=bin(num)[2:]
    assert numBin[0]==0
    if numBin[1]=='1':
        f="DF"
    elif numBin[2]=='1':
        f="MF"
    else:
        f="None"
    numBin=numBin[3:]
    fo=int(numBin,2)
    return {"flags":f,"Fragment offset":fo}.update(ip_TTL(sr,IHL-2,totalL-2))

def ip_TTL(s:str,IHL:int,totalL:int):
    """
    Identification : 1 octet
    Time To Live, donner une indication de la limite supérieure du temps de vie d'un datagramme
    """
    l,sr=discharge(s,1)
    ttl=h2d_byte(l[0])
    return {"TTL":ttl}.update(ip_protocol(sr,IHL-1,totalL-1))

def ip_protocol(s:str,IHL:int,totalL:int):
    """
    Identification : 1 octet
    Le protocole (de niveau supérieur) utilisé pour le champ de données du datagramme.
    """
    l,sr=discharge(s,1)
    protocol=h2d_byte(l[0])
    assert protocol in (1,6,17)
    prot_Name={1:"ICMP",6:"TCP",17:"UDP"}[protocol]
    return {"protocol":prot_Name}.update(ip_header_checksum(sr,IHL-1,totalL-1,prot_Name))

def ip_header_checksum(s:str,IHL:int,totalL:int,protocol:str):
    """
    Header checksum : 2 octets
    Une zone de contrôle d'erreur portant uniquement sur l'en-tête du datagramme
    """
    l,sr=discharge(s,2)
    cs=l[0]+l[1]
    return {"Header checksum":"0x"+cs}.update(ip_src_addr(sr,IHL-2,totalL-2,protocol))