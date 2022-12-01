#capture : capture tous les trames passer sur en0 dans 3 secondes et stocker les ficher en format de .txt
capture:
	tcpdump -i en0 -w trace/trace.pcap & sleep 3 
	python3 transforme.py

#clean : initialiser la répertoire
clean: 
	rm -f trace/*.pcap trace/*.txt
