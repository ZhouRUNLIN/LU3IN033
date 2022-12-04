#capture : capture tous les trames passer sur en0 dans 3 secondes et stocker les ficher en format de .txt
capture:
	tcpdump -i en0 tcp -w trame/trace.pcap & sleep 5 
	python3 transforme.py
	rm -f trame/trace.pcap

#clean : initialiser la répertoire
clean: 
	rm -f trame/*.txt
