from html.parser import HTMLParser
import urllib.request
import string

class MyHTMLParser(HTMLParser):
	def __init__(self,strict=False):
		HTMLParser.__init__(self,strict)
		self.description=''
		self.solution=''
		self.cvss_score=0.0
		self.cve_id=''
		self.references=[]
		self.products=''
		self.impact=''
		self.attack_from=''
		self.cve=False
		self.desc=False
		self.cvss=False
		self.prod=False
		self.impt=False
		self.ref=False
		self.sol=False
		self.attk=False
		self.td=False
		self.tr=False
		self.font=False
		self.a=False
		

	def handle_starttag(self,tag,attrs):
		if tag == 'td':
			self.td=True
		if tag == 'font':
			self.font=True
		if tag =='a':
			self.a=True
		if tag == 'tr':
			self.tr=True

	def handle_endtag(self,tag):
		if tag == 'td':
			self.td=False
			if self.font == True:
				self.font=False
				self.ref=False
		if tag == 'a':
			self=False
		if tag =='tr':
			self.tr=False

			
	def handle_data(self,data):
		data=data.strip()
		if len(data) == 0:
			return
		if self.desc and self.tr:
			self.description=data
			self.desc=False
		if self.font:
			if self.cvss:
				self.cvss=False
				self.font=False
				self.cvss_score=float(data)
			elif self.prod:
				self.prod=False
				self.font=False
				self.products=data
			elif self.attk:
				self.attk=False
				self.font=False
				self.attack_from=data
			elif self.impt:
				self.impt=False
				self.font=False
				self.impact=data
			elif self.ref:
				if 'http' in  data:
					data=data.strip('.').strip()
					self.references.append(data)
			elif self.sol:
				self.sol=False
				self.font=False
				self.solution=data
		
		if self.td:
			if self.a:
				if self.cve:
					self.cve=False
					self.font=False
					self.cve_id=data
			if data == 'CVE ID:':
				self.cve=True
			elif data == 'Description:':
				self.desc=True
			elif data == 'CVSS Base Score:':
				self.cvss=True
			elif data == 'Affect OS:':
				self.prod=True
			elif data == 'Attack From:':
				self.attk=True
			elif data == 'Impact:':
				self.impt=True
			elif data == 'References:':
				self.ref=True
			elif data == 'Solution:':
				self.sol=True

		
				

	def get_description(self):
		return self.description

	def get_solutions(self):
		return self.solution

	def get_cvss_score(self):
		return self.cvss_score

	def get_cve_id(self):
		return self.cve_id;

	def get_references(self):
		return self.references;

	def get_products(self):
		return self.products;

	def get_impact(self):
		return self.impact

	def get_attack_from(self):
		return self.attack_from
		
def main():
	url='http://vdb.dragonsoft.com/detail.php?id=5002'
	request = urllib.request.Request(url)
	request.add_header("User-Agent", "My Crawler")
	opener = urllib.request.build_opener()
	f = opener.open(request)
	st = f.read().decode('utf-8');
	parse = MyHTMLParser()
	parse.feed(st);
	print('cve: ',parse.get_cve_id())
	print('desc: ',parse.get_description())
	print('soln: ',parse.get_solutions())
	print('cvss: ',parse.get_cvss_score())
	print('ref: ',parse.get_references())
	print('prod: ',parse.get_products())
	print('impact: ',parse.get_impact())
	print('from: ',parse.get_attack_from())
	return 0
	
if __name__ == '__main__':
	main()
 
