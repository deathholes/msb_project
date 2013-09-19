from html.parser import HTMLParser
import urllib.request
import string

class MyHTMLParser(HTMLParser):
	def __init__(self,strict=False):
		HTMLParser.__init__(self,strict)
		self.h1=False
		self.desc=False
		self.description=''
		self.sol=False
		self.solution=''
		self.p=False;
		self.li=False;
		self.ref=False;
		self.references=''
		self.cvss=False;
		self.cvss_score=0.0;
		self.cve=False
		self.cve_id=''
		self.links=[]
		self.prod=False;
		self.products=[]
		self.last_h6=''
		self.h6=False
		self.h7=False
		self.clas=False
		self.attack_from=''
		self.attk=False
		self.impact=''
		self.impt=False
		
		
	def handle_starttag(self, tag, attrs):
		check=False
		if tag == 'h1':
			self.h1=True;
		if tag == 'p':
			self.p=True;
		if tag =='li':
			self.li=True;
		if tag =='a':
			#self.a==True;
			if self.ref:
				for name,value in attrs:
					if name == 'href':
						self.links.append(value);
		if tag == 'h6':
			self.h6=True
		if tag == 'h7':
			self.h7 = True

	def handle_endtag(self, tag):
		if tag == 'h1':
			self.h1=False
		if tag == 'p':
			self.p=False
		if tag == 'li':
			self.li=False
		if tag =='table':
			self.desc=False
			self.sol=False
			self.cvss=False
			self.cve=False
			self.ref=False
			self.prod=False
		if tag == 'h6':
			self.h6=False
		if tag == 'h7':
			self.h7=False
		

	def handle_data(self, data):
		if self.h6:
			self.last_h6=data.strip()+' '
		if self.p == True:
			if self.desc:
				self.desc=False;
				self.description=data;
			elif self.sol:
				self.sol=False;	
				self.solution=data;
			elif self.cvss:
				self.cvss=False
				#print(data[-4:])
				try:
					self.cvss_score=float(data[-4:])
				except:
					self.cvss_score=0.0
					
		if self.prod and self.h7:
			self.products.append(self.last_h6+data.strip());
		if self.attk:
			self.attack_from=data.strip(':').strip()
			self.attk=False
		if self.impt:
			self.impact=data.strip(':').strip()
			self.impt=False
		if self.clas and data == 'Location':
			self.attk=True
		if self.clas and data == 'Impact':
			self.impt=True
			self.clas=False
		if self.li :
			if self.cve:
				self.cve=False
				self.cve_id=data;
			elif 'CVE ID:' in data:
				self.cve = True;
		if self.h1 == True:
			if data == 'Description':
				self.desc=True
			elif data == 'Solution':
				self.sol=True
			elif data == 'References':
				self.ref=True
			elif data == 'CVSSv2 Score':
				self.cvss=True
			elif data == 'Products':
				self.prod=True
			elif data == 'Classification':
				self.clas=True
				
		

	def get_description(self):
		return self.description

	def get_solutions(self):
		return self.solution

	def get_cvss_score(self):
		return self.cvss_score

	def get_cve_id(self):
		return self.cve_id;

	def get_references(self):
		return self.links;

	def get_products(self):
		return self.products;
	def get_attack_from(self):
		return self.attack_from
	def get_impact(self):
		return self.impact
def main():
	url='http://www.osvdb.org/show/osvdb/96779'
	request = urllib.request.Request(url)
	request.add_header("User-Agent", "My Crawler")
	opener = urllib.request.build_opener()
	f = opener.open(request)
	#f = urllib.request.urlopen(url)
	st = f.read().decode('utf-8');
	parse = MyHTMLParser()
	parse.feed(st)
	print('CVE ID:  ',parse.get_cve_id())
	print('DESCRIPTION: ',parse.get_description())
	print('GET_SOLUTIONS: ',parse.get_solutions())
	print('CVSS SCORE: ',parse.get_cvss_score())
	print('REFERENCES: ',parse.get_references())
	print('PRODUCTS: ',parse.get_products())
	print('ATTACK FROM: ',parse.get_attack_from())
	print('IMPACT: ',parse.get_impact())
	return 0

if __name__ == '__main__':
	main()

