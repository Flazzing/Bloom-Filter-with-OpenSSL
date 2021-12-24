# Bloom-Filter-with-OpenSSL
Bloom filter with SHA 512, SHA 384, SHA 256, SHA 224. SHA 1.

Note: Please do not use SHA 1 when implementing your bloom filter, SHA 1 is deemed to be longer secure.

To compile the program: make

To run the program: 

		./enc -d dictionary.txt -i sample_input.txt

		(Note: This dictionary is changed by removing the space character after the text)
		./enc -d dictionary2.txt -i sample_input.txt
		

Note (Please read): 

The sample dictionary have some problem. Given a bad password within the dictionary.txt, there will be some space character after the text, which results to a no match. I will provide an extra dictionary file called dictionary2.txt that I have made some changes that at least fulfil the given sample_input.txt. Do note that I didnt remove all spaces within the dictionary.txt, I merely only changed the input password within the dictionary. 

For example: 

 dictionary: "ThisIsPassword     "
 input 	   : "ThisIsPassword"

 (Note: This is not a match within the bloom filter".)

 dictionary and input will result to a different hash value

Appeal (Please read): 
I really prefer to not lose 20% of the coursework because I spent all my late days fixing an issue that is not really a problem. Is there anyway to work around this? 
