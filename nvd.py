from html.parser import HTMLParser
import urllib.request
import string

class MyHTMLParser(HTMLParser):
	def __init__(self,strict=False):
		HTMLParser.__init__(self,strict)
		self.cve_id=''
		self.description=''
		self.cvss_score=0.0
		self.products=''
		self.impact=''
		self.attack_from=''
		self.references=[]
		self.cve=False
		self.desc=False
		self.cvss=False
		self.prod=False
		self.impt=False
		self.attk=False
		self.ref=False
		self.h3=False
		self.h4=False
		self.p=False
		self.a=False
		self.span=0

	def handle_starttag(self,tag,attrs):
		if tag == 'h3':
			self.h3=True
		if tag == 'h4':
			self.h4=True
		if tag =='p':
			self.p=True
		if tag == 'a':
			self.a=True
		if tag == 'span':
			if self.span !=0:
				self.span+=1
			for name,value in attrs:
				if name=='id' and value=='j_id198':
					self.span=1

	def handle_endtag(self,tag):
		if tag == 'h3':
			self.h3=False
		if tag == 'h4':
			self.h4=False
		if tag == 'p':
			self.p=False
			self.desc=False
		if tag == 'a':
			self.a=False
		if tag == 'span':
			if self.span!=0:
				self.span-=1

	def handle_data(self,data):
		data=data.strip()
		if len(data) == 0:
			return
		if self.desc:
			self.description+=data
		if self.cvss:
			try:
				self.cvss_score=float(data[-4:])
				self.cvss=False
			except:
				return
		if self.attk:
			self.attack_from=data
			self.attk=False
		if self.impt:
			self.impact=data
			self.impt=False
		if self.h3:
			data=data.strip()
			self.cve_id=data[-9:]
		if self.a and self.ref and self.span!=0:
			self.references.append(data)
		
		if self.h4:
			if data == 'Overview':
				self.desc=True
			if data == 'Impact':
				self.cvss=True
			if 'References' in data:
				self.ref=True
			if 'software'in data:
				self.prod=True
				
		if data == 'Access Vector:':
			self.attk=True
		if data == 'Impact Type:':
			self.impt=True

	def get_description(self):
		return self.description

	def get_cvss_score(self):
		return self.cvss_score

	def get_cve_id(self):
		return self.cve_id;

	def get_references(self):
		return self.references;

	def get_products(self):
		return self.products;

	def get_attack_from(self):
		return self.attack_from;

	def get_impact(self):
		return self.impact;

def main():
	url='http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2012-6606'
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
	print('CVSS SCORE: ',parse.get_cvss_score())
	print('REFERENCES: ',parse.get_references())
	print('PRODUCTS: ',parse.get_products())
	print('ATTACK FROM: ',parse.get_attack_from())
	print('IMPACT: ',parse.get_impact())
	return 0

if __name__ == '__main__':
	main()

